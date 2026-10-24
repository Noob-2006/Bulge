//! `bulge channels serve`: the poll loops, per-chat queues, and shutdown.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use bulge_channels::access::AccessConfig;
use bulge_channels::{Channel, ChannelError, Inbound};
use sha2::Digest;
use bulge_channels::commands::{self, Parsed};
use futures::FutureExt;
use tokio::sync::mpsc;
use super::{ChannelsConfig, Hub, JobRunner, Summarizer, connect};

/// Poll one channel forever, handing messages to per-chat queues.
pub(crate) async fn poll_loop(channel: Arc<dyn Channel>, access: AccessConfig, hub: Arc<Hub>, queues: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Inbound>>>>) {
    let mut backoff = 1u64;
    loop {
        // A panic while reading one batch (a malformed message) must not end
        // this channel silently: it is reported and the loop goes on.
        // When the daemon stops, no new batch is taken (a poll in progress is
        // dropped before it commits its position, so nothing is skipped).
        let polled = tokio::select! {
            () = hub.closing.cancelled() => return,
            polled = std::panic::AssertUnwindSafe(channel.poll()).catch_unwind() => polled,
        };
        let polled = match polled {
            Ok(polled) => polled,
            Err(_) => {
                eprintln!("{}: reading messages panicked; retrying in {backoff}s", channel.name());
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
                continue;
            }
        };
        match polled {
            Ok(batch) => {
                backoff = 1;
                if let Some(cursor) = channel.cursor()
                    && let Ok(mut state) = hub.state.lock()
                    && let Err(error) = state.set_cursor(channel.name(), &cursor)
                {
                    eprintln!("{}: poll position not saved: {error}", channel.name());
                }
                for message in batch {
                    enqueue(&channel, &access, &hub, &queues, message);
                }
            }
            Err(error) if error.is_fatal() => {
                eprintln!("{error}; this channel stops (fix its credentials and restart)");
                return;
            }
            Err(error) => {
                let wait = match &error {
                    ChannelError::Transient { retry_after_secs: Some(secs), .. } => *secs,
                    _ => backoff,
                };
                eprintln!("{error}; retrying in {wait}s");
                tokio::time::sleep(Duration::from_secs(wait)).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

/// One queue (and worker) per chat, so a chat's messages run in order.
pub(crate) fn enqueue(channel: &Arc<dyn Channel>, access: &AccessConfig, hub: &Arc<Hub>, queues: &Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Inbound>>>>, message: Inbound) {
    // `/stop`, `/status`, `/help` must not wait behind the task they are about.
    hub.inflight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if matches!(commands::parse(&message.text), Parsed::Command(command, _) if command.urgent) {
        let (channel, access, hub) = (channel.clone(), access.clone(), hub.clone());
        tokio::spawn(async move {
            let _ = std::panic::AssertUnwindSafe(hub.handle(channel.as_ref(), &access, message)).catch_unwind().await;
            hub.inflight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
        return;
    }
    // In groups each person has their own queue: one long task must not
    // hold up everyone else in the group.
    let key = if message.is_group { format!("{}:{}", message.chat_key(), message.sender_id) } else { message.chat_key() };
    let Ok(mut map) = queues.lock() else { return };
    let sender = map.entry(key).or_insert_with(|| {
        let (tx, mut rx) = mpsc::unbounded_channel::<Inbound>();
        let (channel, access, hub) = (channel.clone(), access.clone(), hub.clone());
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                // One message that panics must not stop this chat's queue.
                if std::panic::AssertUnwindSafe(hub.handle(channel.as_ref(), &access, message)).catch_unwind().await.is_err() {
                    eprintln!("{}: handling a message panicked; the chat goes on", channel.name());
                }
                hub.inflight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        tx
    });
    let _ = sender.send(message);
}

/// Connect every enabled account and serve until interrupted.
pub async fn serve(home: &Path, config: ChannelsConfig, runner: Arc<dyn JobRunner>, summarizer: Arc<dyn Summarizer>) -> Result<(), String> {
    let dir = home.join(".bulge/channels");
    // One daemon at a time: two would both poll the same bot (Telegram
    // answers 409 Conflict) and both answer every message.
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let _single = bulge_util::fs::single_instance(&dir.join("serve.lock"), "`bulge channels serve`")?;
    let mut hub = Hub::new(runner.clone(), Some(summarizer), home, &config.workspace, config.max_parallel_jobs)?;
    hub.about = format!("模型 {} · 推理強度 {}", config.model, config.reasoning_effort);
    let hub = Arc::new(hub);
    // Group history kept in the earlier per-group JSON-lines files moves into the archive.
    for account in &config.accounts {
        for group in &account.access.open_groups {
            let chat = format!("{}:{}:{group}", account.kind, account.account);
            let digest = sha2::Sha256::digest(chat.as_bytes());
            let name: String = digest.iter().take(12).map(|b| format!("{b:02x}")).collect();
            match hub.history.import_jsonl(&chat, &dir.join("history").join(format!("{name}.jsonl"))) {
                Ok(0) => {}
                Ok(n) => eprintln!("chat archive: imported {n} earlier message(s) of {chat}"),
                Err(error) => eprintln!("chat archive: {error}"),
            }
        }
    }
    let queues = Arc::new(Mutex::new(HashMap::new()));
    let mut running = 0;
    for account in config.accounts.iter().filter(|a| a.enabled) {
        let name = format!("{}:{}", account.kind, account.account);
        let cursor = hub.state.lock().ok().and_then(|s| s.cursor(&name).map(str::to_owned));
        match connect(home, account, cursor.as_deref()).await {
            Ok(channel) => {
                eprintln!("{name}: connected");
                if let Err(error) = channel.register_commands(commands::COMMANDS).await {
                    eprintln!("{name}: command menu not published: {error}");
                }
                running += 1;
                tokio::spawn(poll_loop(channel, account.access.clone(), hub.clone(), queues.clone()));
            }
            Err(error) => eprintln!("{name}: not connected: {error}"),
        }
    }
    if running == 0 {
        return Err("no channel could be connected".into());
    }
    tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
    // Stop taking messages, then finish what was taken (its app already
    // considers it delivered). A second Ctrl-C stops at once.
    hub.closing.cancel();
    eprintln!("stopping: finishing {} message(s) already taken (Ctrl-C again to stop now)", hub.inflight.load(std::sync::atomic::Ordering::SeqCst));
    let drained = async {
        // Then the sessions still learning after their reply went out.
        while hub.inflight.load(std::sync::atomic::Ordering::SeqCst) + runner.finishing() > 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    tokio::select! {
        () = drained => eprintln!("stopped"),
        _ = tokio::signal::ctrl_c() => {
            eprintln!("stopped with {} message(s) unfinished", hub.inflight.load(std::sync::atomic::Ordering::SeqCst));
            for (stop, _) in hub.running.lock().map(|r| r.values().cloned().collect::<Vec<_>>()).unwrap_or_default() {
                stop.cancel();
            }
        }
    }
    Ok(())
}
