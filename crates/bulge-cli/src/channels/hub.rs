//! The hub: one admitted message in, commands or a job, the reply out.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use bulge_channels::access::{AccessConfig, Decision, PairingStore, now_secs};
use bulge_channels::history::{ChatArchive, Entry as HistoryEntry, summary_prompt};
use bulge_channels::state::ChannelState;
use bulge_channels::{Attachment, Channel, Inbound, reply_long, send_long};
use sha2::Digest;
use tokio_util::sync::CancellationToken;
use bulge_channels::commands::{self, Parsed};
use tokio::sync::Semaphore;
use super::{JobRunner, Space, Summarizer, chat_history_tool, kind_label, slug};

/// Shared daemon state.
pub struct Hub {
    pub runner: Arc<dyn JobRunner>,
    pub pairing: Mutex<PairingStore>,
    pub state: Mutex<ChannelState>,
    pub jobs: Arc<Semaphore>,
    pub home: PathBuf,
    /// The owner's workspace.
    pub workspace: PathBuf,
    /// Long memory of the groups bulge listens in.
    pub history: Arc<ChatArchive>,
    /// Summarizes old stretches of group history (none: never compress).
    pub summarizer: Option<Arc<dyn Summarizer>>,
    /// Chats whose compression is running.
    pub compacting: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Files sent without a request, per chat + sender, until their next message.
    pub stash: Mutex<HashMap<String, Vec<(Attachment, u64)>>>,
    /// Turns running now: conversation key → (stop switch, started at).
    pub running: Mutex<HashMap<String, (CancellationToken, std::time::Instant)>>,
    /// The model line `/status` shows.
    pub about: String,
    /// Messages taken from the apps and not yet fully handled.
    pub inflight: Arc<std::sync::atomic::AtomicUsize>,
    /// Set when the daemon is stopping: no new messages are taken.
    pub closing: CancellationToken,
}

impl Hub {
    pub fn new(runner: Arc<dyn JobRunner>, summarizer: Option<Arc<dyn Summarizer>>, home: &Path, workspace: &Path, max_parallel_jobs: usize) -> Result<Self, String> {
        let dir = home.join(".bulge/channels");
        Ok(Hub {
            runner,
            pairing: Mutex::new(PairingStore::load(&dir.join("pairing.json"))?),
            state: Mutex::new(ChannelState::load(&dir.join("state.json"))?),
            jobs: Arc::new(Semaphore::new(max_parallel_jobs)),
            home: home.to_path_buf(),
            workspace: workspace.to_path_buf(),
            history: Arc::new(ChatArchive::open(&dir.join("history.db"))?),
            summarizer,
            compacting: Arc::new(Mutex::new(std::collections::HashSet::new())),
            stash: Mutex::new(HashMap::new()),
            running: Mutex::new(HashMap::new()),
            about: String::new(),
            inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            closing: CancellationToken::new(),
        })
    }

    /// The space this sender's turns run in (created on first use).
    ///
    /// Requests from groups never get the owner's space, the owner's own
    /// included: the group's conversation comes with them, and anyone in the
    /// group can write into it. Each person gets a space per group.
    pub fn space(&self, channel: &dyn Channel, access: &AccessConfig, message: &Inbound) -> Result<Space, String> {
        let owner = channel.authenticates_senders() || access.allow_from.iter().any(|id| id == &message.sender_id);
        if owner && !message.is_group {
            return Ok(Space { workspace: self.workspace.clone(), store_root: self.home.join(".bulge/jobs"), harness_dir: self.home.join(".bulge/harness"), owner: true });
        }
        let room = if message.is_group { message.chat_id.as_str() } else { "" };
        // Readable, and unique even when two ids slug alike.
        let digest = sha2::Sha256::digest(format!("{}\0{}\0{room}", message.channel, message.sender_id).as_bytes());
        let tag: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
        let base = self.home.join(".bulge/channels/users").join(format!("{}-{}-{tag}", slug(&message.channel), slug(&message.sender_id)));
        let space = Space { workspace: base.join("workspace"), store_root: base.join("jobs"), harness_dir: base.join("harness"), owner: false };
        for dir in [&space.workspace, &space.store_root, &space.harness_dir] {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
        }
        Ok(space)
    }

    /// Summarize old stretches of `chat` in the background until nothing is
    /// left to compress (one task per chat at a time).
    pub(crate) fn compress(&self, chat: &str) {
        let Some(summarizer) = self.summarizer.clone() else { return };
        let Ok(mut running) = self.compacting.lock() else { return };
        if !running.insert(chat.to_owned()) {
            return;
        }
        drop(running);
        let (archive, compacting, chat) = (self.history.clone(), self.compacting.clone(), chat.to_owned());
        tokio::spawn(async move {
            loop {
                let work = match archive.next_compaction(&chat) {
                    Ok(Some(work)) => work,
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("chat archive: {error}");
                        break;
                    }
                };
                match summarizer.summarize(summary_prompt(&work)).await {
                    Ok(text) => {
                        if let Err(error) = archive.store_summary(&work, &text) {
                            eprintln!("chat archive: {error}");
                            break;
                        }
                        eprintln!("chat archive: summarized {} item(s) of {chat} into level {}", work.items.len(), work.level);
                    }
                    Err(error) => {
                        // Left for the next message to retry; raw messages are kept regardless.
                        eprintln!("chat archive: summary failed, will retry later: {error}");
                        break;
                    }
                }
            }
            if let Ok(mut running) = compacting.lock() {
                running.remove(&chat);
            }
        });
    }

    /// Handle one inbound message end to end (history, access, files,
    /// commands, the job, the reply).
    pub async fn handle(&self, channel: &dyn Channel, access: &AccessConfig, message: Inbound) {
        let now = now_secs();
        if message.sender_id.trim().is_empty() {
            // Without a sender there is no space or conversation to keep apart.
            eprintln!("{}: ignored a message with no sender id", channel.name());
            return;
        }
        let chat_key = message.chat_key();
        let listening = message.is_group && access.listens_in(&message.chat_id);
        // The conversation before this message (with what relates to it),
        // then record this message.
        let group_context = if listening {
            self.history.context(&chat_key, &message.text).unwrap_or_else(|error| {
                eprintln!("{}: group history unavailable: {error}", channel.name());
                None
            })
        } else {
            None
        };
        if listening {
            let files: Vec<&str> = message.attachments.iter().map(|f| kind_label(&f.kind)).collect();
            let text = match (message.text.trim(), files.is_empty()) {
                (text, true) => text.to_owned(),
                (text, false) => format!("{text} [傳了{}]", files.join("、")).trim().to_owned(),
            };
            let entry = HistoryEntry { at: now, sender_id: message.sender_id.clone(), sender_name: message.sender_name.clone(), text };
            match self.history.append(&chat_key, &entry) {
                Ok(()) => self.compress(&chat_key),
                Err(error) => eprintln!("{}: group history not recorded: {error}", channel.name()),
            }
        }

        // Channels that authenticate senders cryptographically (remote
        // devices) admit only paired devices before a message gets here.
        let decision = if channel.authenticates_senders() { Ok(Decision::Admit) } else { self.pairing.lock().map_err(|_| "pairing store poisoned".to_string()).and_then(|mut p| p.decide(access, &message, now)) };
        let decision = match decision {
            Ok(decision) => decision,
            Err(error) => {
                eprintln!("{}: access check failed, message dropped: {error}", channel.name());
                return;
            }
        };
        match decision {
            Decision::Ignore(reason) => {
                // A file posted in a group before the request that uses it.
                if listening && !message.attachments.is_empty() {
                    self.put_aside(&Self::stash_key(&message), message.attachments.clone(), now);
                }
                eprintln!("{}: ignored a message from {} ({reason})", channel.name(), message.sender_id);
                return;
            }
            Decision::Challenge(text) => {
                eprintln!("{}: sent a pairing code to {} ({})", channel.name(), message.sender_id, message.sender_name);
                let _ = send_long(channel, &message.chat_id, &text).await;
                return;
            }
            Decision::Admit => {}
        }

        // In groups each person has their own conversation.
        let key = if message.is_group { format!("{chat_key}:{}", message.sender_id) } else { chat_key.clone() };
        let space = match self.space(channel, access, &message) {
            Ok(space) => space,
            Err(error) => {
                eprintln!("{}: {error}", channel.name());
                let _ = reply_long(channel, &message, &format!("無法準備工作區：{error}")).await;
                return;
            }
        };
        let stash_key = Self::stash_key(&message);
        let text = message.text.trim();
        if text.is_empty() {
            if !message.attachments.is_empty() {
                self.put_aside(&stash_key, message.attachments.clone(), now);
                let count = self.stash.lock().ok().and_then(|s| s.get(&stash_key).map(Vec::len)).unwrap_or(0);
                let _ = reply_long(channel, &message, &format!("收到 {count} 個檔案。接著傳文字告訴我要怎麼處理（30 分鐘內有效）。")).await;
            }
            return;
        }
        let reply = match commands::parse(text) {
            Parsed::Command(command, _) if command.name == "help" => commands::help(),
            Parsed::Command(command, _) if command.name == "new" => match self.state.lock().map_err(|_| "state poisoned".to_string()).and_then(|mut s| s.forget_conversation(&key)) {
                Ok(()) => "好，下一則訊息會開始新的對話。".into(),
                Err(error) => format!("無法開新對話：{error}"),
            },
            Parsed::Command(command, _) if command.name == "undo" => match self.conversation(&key) {
                Some(job) => self.runner.undo(&job, &space).unwrap_or_else(|e| format!("回復失敗：{e}")),
                None => "這個聊天還沒有任務。".into(),
            },
            Parsed::Command(command, _) if command.name == "stop" => match self.running.lock().ok().and_then(|r| r.get(&key).map(|(stop, _)| stop.clone())) {
                Some(stop) => {
                    stop.cancel();
                    "好，正在停止這個任務。".into()
                }
                None => "現在沒有正在跑的任務。".into(),
            },
            Parsed::Command(command, _) if command.name == "status" => self.status(&key, &space),
            Parsed::Command(command, _) => format!("/{} 還沒有實作。", command.name),
            Parsed::Unknown(name) => format!("不認得 /{name}。傳 /help 看可以用的指令。"),
            Parsed::Text => {
                // Files put aside earlier go with this request (not with commands).
                let mut files = self.take_aside(&stash_key, now);
                files.extend(message.attachments.iter().cloned());
                let (saved, failed) = self.receive(channel, &files, &space.workspace).await;
                let mut goal = String::new();
                if let Some(context) = &group_context {
                    goal.push_str(context);
                    goal.push_str("\n\n");
                }
                if message.is_group {
                    let who = if message.sender_name.is_empty() { message.sender_id.as_str() } else { message.sender_name.as_str() };
                    goal.push_str(&format!("{} 在群組裡請你：\n", bulge_channels::history::neutralize(who)));
                }
                goal.push_str(text);
                if !saved.is_empty() {
                    goal.push_str(&format!("\n\n<attachments note=\"Files the requester sent, saved in the workspace. Look at images with the view_image tool when you have it.\">\n{}\n</attachments>", saved.join("\n")));
                }
                let tools = if listening { vec![chat_history_tool(self.history.clone(), chat_key.clone())] } else { Vec::new() };
                let mut reply = self.run_turn(channel, &message, &key, text, goal, space, tools).await;
                if !failed.is_empty() {
                    reply = format!("（有 {} 個檔案沒有收到：{}）\n\n{reply}", failed.len(), failed.join("；"));
                }
                reply
            }
        };
        if let Err(error) = reply_long(channel, &message, &reply).await {
            eprintln!("{}: could not send the reply: {error}", channel.name());
        }
    }

    /// The `/status` reply.
    pub(crate) fn status(&self, key: &str, space: &Space) -> String {
        let task = match self.running.lock().ok().and_then(|r| r.get(key).map(|(_, at)| at.elapsed().as_secs())) {
            Some(secs) => format!("有一個任務在跑（{secs} 秒），傳 /stop 可以停止"),
            None => "沒有任務在跑".into(),
        };
        let conversation = self.conversation(key).map_or_else(|| "下一則訊息會開始新的對話".to_owned(), |job| format!("對話 {job}"));
        let room = if space.owner { "主人的工作區" } else { "你自己的獨立工作區" };
        let about = if self.about.is_empty() { String::new() } else { format!("\n{}", self.about) };
        format!("{task}\n{conversation}\n{room}{about}")
    }

    pub(crate) fn conversation(&self, key: &str) -> Option<String> {
        self.state.lock().ok().and_then(|s| s.conversation(key).map(str::to_owned))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_turn(&self, channel: &dyn Channel, message: &Inbound, key: &str, title: &str, goal: String, space: Space, tools: Vec<crate::run::ExtraTool>) -> String {
        // Registered before waiting for a free slot, so /stop also stops a
        // task that is still waiting to start.
        let stop = CancellationToken::new();
        if let Ok(mut running) = self.running.lock() {
            running.insert(key.to_owned(), (stop.clone(), std::time::Instant::now()));
        }
        let permit = tokio::select! {
            permit = self.jobs.clone().acquire_owned() => permit,
            () = stop.cancelled() => {
                if let Ok(mut running) = self.running.lock() {
                    running.remove(key);
                }
                return "已停止（還沒開始）。".into();
            }
        };
        let Ok(permit) = permit else { return "bulge 正在關閉。".into() };
        let job = self.conversation(key);
        // The runner holds the slot until the job has fully finished (its
        // learning pass and VM shutdown run after the reply).
        let work = self.runner.run(title, goal, job, space, tools, stop.clone(), permit);
        tokio::pin!(work);
        // Keep the app's "typing…" indicator alive while the job runs.
        let result = loop {
            channel.typing(&message.chat_id).await;
            tokio::select! {
                result = &mut work => break result,
                () = tokio::time::sleep(Duration::from_secs(4)) => {}
            }
        };
        if let Ok(mut running) = self.running.lock() {
            running.remove(key);
        }
        // Whatever happened, a job that exists stays this chat's conversation
        // (stopped or failed turns included), so the next message continues it.
        let job_id = match &result {
            Ok(reply) => Some(reply.job_id.clone()),
            Err(failure) => failure.job_id.clone(),
        };
        if let Some(job_id) = &job_id
            && let Ok(mut state) = self.state.lock()
            && let Err(error) = state.set_conversation(key, job_id)
        {
            eprintln!("{}: conversation not remembered: {error}", channel.name());
        }
        if stop.is_cancelled() {
            return "已停止。".into();
        }
        match result {
            Ok(reply) => reply.text,
            Err(error) => format!("任務沒有完成：{error}"),
        }
    }
}
