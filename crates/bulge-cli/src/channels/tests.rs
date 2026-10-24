use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use bulge_channels::access::{AccessConfig, now_secs};
use bulge_channels::{Attachment, Channel, ChannelError, Inbound};
use tokio_util::sync::CancellationToken;
use bulge_store::Autonomy;
use futures::FutureExt;
use futures::future::BoxFuture;

/// A chat app double: records what was sent; serves files by source.
#[derive(Default)]
struct FakeChannel {
    sent: Mutex<Vec<(String, String)>>,
    files: HashMap<String, Vec<u8>>,
}

impl Channel for FakeChannel {
    fn name(&self) -> &str {
        "fake:main"
    }
    fn text_limit(&self) -> usize {
        100
    }
    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
        async { Ok(Vec::new()) }.boxed()
    }
    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
        self.sent.lock().unwrap().push((chat_id.to_owned(), text.to_owned()));
        async { Ok(()) }.boxed()
    }
    fn fetch<'a>(&'a self, attachment: &'a Attachment, _max: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        let found = self.files.get(&attachment.source).cloned();
        async move { found.ok_or(ChannelError::Other { channel: "fake:main".into(), message: "gone".into() }) }.boxed()
    }
}

/// Records goals, the conversation each continued and the space it ran in.
#[derive(Default)]
struct FakeRunner {
    runs: Mutex<Vec<(String, Option<String>)>>,
    spaces: Mutex<Vec<Space>>,
}

impl JobRunner for FakeRunner {
    fn run(&self, title: &str, goal: String, job_id: Option<String>, space: Space, _tools: Vec<crate::run::ExtraTool>, _cancel: CancellationToken, _slot: tokio::sync::OwnedSemaphorePermit) -> BoxFuture<'static, Result<JobReply, crate::run::RunFailure>> {
        let mut runs = self.runs.lock().unwrap();
        runs.push((goal.clone(), job_id.clone()));
        self.spaces.lock().unwrap().push(space);
        let id = job_id.unwrap_or_else(|| format!("j-{}", runs.len()));
        let title = title.to_owned();
        async move { Ok(JobReply { job_id: id, text: format!("done: {title}") }) }.boxed()
    }
    fn undo(&self, job_id: &str, _space: &Space) -> Result<String, String> {
        Ok(format!("undid {job_id}"))
    }
}

fn hub(tag: &str, runner: Arc<FakeRunner>) -> Hub {
    let home = std::env::temp_dir().join(format!("bulge-hub-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    Hub::new(runner, None, &home, &home.join("owner-workspace"), 1).unwrap()
}

fn message(sender: &str, text: &str) -> Inbound {
    Inbound {
        channel: "fake:main".into(),
        chat_id: format!("chat-{sender}"),
        sender_id: sender.into(),
        sender_name: sender.into(),
        is_group: false,
        mentioned: true,
        text: text.into(),
        message_id: "1".into(),
        attachments: Vec::new(),
    }
}

#[tokio::test]
async fn owner_turns_continue_one_conversation_and_commands_work() {
    let runner = Arc::new(FakeRunner::default());
    let hub = hub("owner", runner.clone());
    let channel = FakeChannel::default();
    let access = AccessConfig { allow_from: vec!["owner".into()], ..Default::default() };
    hub.handle(&channel, &access, message("owner", "整理報告")).await;
    hub.handle(&channel, &access, message("owner", "再加一節結論")).await;
    hub.handle(&channel, &access, message("owner", "/undo")).await;
    hub.handle(&channel, &access, message("owner", "/new")).await;
    hub.handle(&channel, &access, message("owner", "新題目")).await;
    let runs = runner.runs.lock().unwrap().clone();
    assert_eq!(runs, [("整理報告".into(), None), ("再加一節結論".into(), Some("j-1".into())), ("新題目".into(), None)]);
    let sent: Vec<String> = channel.sent.lock().unwrap().iter().map(|(_, t)| t.clone()).collect();
    assert_eq!(sent[0], "done: 整理報告");
    assert_eq!(sent[2], "undid j-1");
    assert!(sent[3].contains("新的對話"));
}

#[tokio::test]
async fn strangers_get_a_pairing_code_and_never_run_a_job() {
    let runner = Arc::new(FakeRunner::default());
    let hub = hub("stranger", runner.clone());
    let channel = FakeChannel::default();
    hub.handle(&channel, &AccessConfig::default(), message("stranger", "rm -rf everything")).await;
    assert!(runner.runs.lock().unwrap().is_empty());
    let sent = channel.sent.lock().unwrap().clone();
    assert!(sent.iter().any(|(_, t)| t.contains("bulge channels approve")));
    // After approval the same sender is served.
    let code = hub.pairing.lock().unwrap().pending(now_secs()).unwrap()[0].code.clone();
    hub.pairing.lock().unwrap().approve(&code, now_secs()).unwrap();
    hub.handle(&channel, &AccessConfig::default(), message("stranger", "hello")).await;
    assert_eq!(runner.runs.lock().unwrap().len(), 1);
    assert!(!runner.spaces.lock().unwrap()[0].owner, "approved friends are guests with their own space");
}

fn group(sender: &str, text: &str, mentioned: bool) -> Inbound {
    Inbound { chat_id: "Cgroup".into(), is_group: true, mentioned, ..message(sender, text) }
}

#[tokio::test]
async fn open_groups_serve_anyone_in_their_own_space_with_the_chat_as_context() {
    let runner = Arc::new(FakeRunner::default());
    let hub = hub("group", runner.clone());
    let mut channel = FakeChannel::default();
    channel.files.insert("img-1".into(), b"\x89PNG\r\n rest".to_vec());
    let access = AccessConfig { allow_from: vec!["owner".into()], open_groups: vec!["Cgroup".into()], ..Default::default() };

    hub.handle(&channel, &access, group("amy", "明天考第三課", false)).await;
    // A photo first (not addressed), then the request.
    let photo = Inbound { attachments: vec![Attachment { kind: "image".into(), name: None, source: "img-1".into(), size: Some(12) }], ..group("ben", "", false) };
    hub.handle(&channel, &access, photo).await;
    hub.handle(&channel, &access, group("ben", "幫我看這張圖", true)).await;
    hub.handle(&channel, &access, group("owner", "整理今天的討論", true)).await;
    hub.handle(&channel, &access, group("ben", "再詳細一點", true)).await;

    let runs = runner.runs.lock().unwrap().clone();
    let spaces = runner.spaces.lock().unwrap().clone();
    assert_eq!(runs.len(), 3);
    let (ben_goal, ben_job) = &runs[0];
    assert!(ben_goal.starts_with("<group-chat") && ben_goal.contains("amy: 明天考第三課"), "{ben_goal}");
    assert!(ben_goal.contains("ben 在群組裡請你：\n幫我看這張圖"));
    assert!(ben_goal.contains("inbox/image-") && ben_goal.contains(".png（圖片"), "the photo was fetched and named by its bytes");
    assert!(ben_job.is_none());
    // Ben is a guest with his own workspace, where the photo landed.
    assert!(!spaces[0].owner);
    assert_ne!(spaces[0].workspace, hub.workspace);
    assert_eq!(std::fs::read_dir(spaces[0].workspace.join("inbox")).unwrap().count(), 1);
    // The owner, in the same group, also gets a space of their own there
    // (never the main workspace: the group's text comes with the request).
    assert!(!spaces[1].owner && spaces[1].workspace != hub.workspace && spaces[1].workspace != spaces[0].workspace);
    assert!(runs[1].1.is_none(), "not ben's conversation");
    // Ben's follow-up continues his own conversation.
    assert_eq!(runs[2].1.as_deref(), Some("j-1"));
    assert_eq!(spaces[2], spaces[0]);
    let sent = channel.sent.lock().unwrap().clone();
    assert!(sent.iter().all(|(chat, _)| chat == "Cgroup"));
    assert!(sent[0].1.starts_with("ben：\n"), "replies say whom they answer");
}

/// Waits until cancelled, then reports what it was doing.
struct SlowRunner;

impl JobRunner for SlowRunner {
    fn run(&self, _title: &str, _goal: String, _job: Option<String>, _space: Space, _tools: Vec<crate::run::ExtraTool>, cancel: CancellationToken, _slot: tokio::sync::OwnedSemaphorePermit) -> BoxFuture<'static, Result<JobReply, crate::run::RunFailure>> {
        async move {
            cancel.cancelled().await;
            Ok(JobReply { job_id: "j-slow".into(), text: "partial".into() })
        }
        .boxed()
    }
    fn undo(&self, _job: &str, _space: &Space) -> Result<String, String> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn stop_jumps_the_queue_and_cancels_the_running_task() {
    let home = std::env::temp_dir().join(format!("bulge-hub-stop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let hub = Arc::new(Hub::new(Arc::new(SlowRunner), None, &home, &home.join("ws"), 1).unwrap());
    let channel: Arc<dyn Channel> = Arc::new(FakeChannel::default());
    let access = AccessConfig { allow_from: vec!["owner".into()], ..Default::default() };
    let queues = Arc::new(Mutex::new(HashMap::new()));
    enqueue(&channel, &access, &hub, &queues, message("owner", "做一件很久的事"));
    for _ in 0..50 {
        if !hub.running.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(hub.status("fake:main:chat-owner", &hub.space(channel.as_ref(), &access, &message("owner", "")).unwrap()).contains("有一個任務在跑"));
    // Queued behind the task, /stop would never run; it must jump ahead.
    enqueue(&channel, &access, &hub, &queues, message("owner", "/stop"));
    for _ in 0..100 {
        if hub.running.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(hub.running.lock().unwrap().is_empty(), "the task was stopped");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(hub.conversation("fake:main:chat-owner").as_deref(), Some("j-slow"), "the stopped job's conversation continues");
}

/// Creates its job, then fails mid-turn.
struct FailingRunner;

impl JobRunner for FailingRunner {
    fn run(&self, _title: &str, _goal: String, job: Option<String>, _space: Space, _tools: Vec<crate::run::ExtraTool>, _cancel: CancellationToken, _slot: tokio::sync::OwnedSemaphorePermit) -> BoxFuture<'static, Result<JobReply, crate::run::RunFailure>> {
        let job_id = job.unwrap_or_else(|| "j-failed".into());
        async move { Err(crate::run::RunFailure { job_id: Some(job_id), message: "model error".into() }) }.boxed()
    }
    fn undo(&self, _job: &str, _space: &Space) -> Result<String, String> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn a_failed_turn_keeps_its_conversation() {
    let home = std::env::temp_dir().join(format!("bulge-hub-fail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let hub = Hub::new(Arc::new(FailingRunner), None, &home, &home.join("ws"), 1).unwrap();
    let channel = FakeChannel::default();
    let access = AccessConfig { allow_from: vec!["owner".into()], ..Default::default() };
    hub.handle(&channel, &access, message("owner", "做事")).await;
    assert!(channel.sent.lock().unwrap()[0].1.contains("任務沒有完成：model error"));
    assert_eq!(hub.conversation("fake:main:chat-owner").as_deref(), Some("j-failed"), "the next message continues the job");
}

#[tokio::test]
async fn status_and_unknown_commands_answer_without_running_a_job() {
    let runner = Arc::new(FakeRunner::default());
    let hub = hub("cmds", runner.clone());
    let channel = FakeChannel::default();
    let access = AccessConfig { allow_from: vec!["owner".into()], ..Default::default() };
    hub.handle(&channel, &access, message("owner", "/status")).await;
    hub.handle(&channel, &access, message("owner", "/frobnicate")).await;
    hub.handle(&channel, &access, message("owner", "/stop")).await;
    hub.handle(&channel, &access, message("owner", "/help")).await;
    assert!(runner.runs.lock().unwrap().is_empty());
    let sent: Vec<String> = channel.sent.lock().unwrap().iter().map(|(_, t)| t.clone()).collect();
    assert!(sent[0].contains("沒有任務在跑") && sent[0].contains("主人的工作區"));
    assert!(sent[1].contains("不認得 /frobnicate"));
    assert!(sent[2].contains("沒有正在跑的任務"));
    assert!(sent[3..].concat().contains("/stop — 停止正在跑的任務"), "help (split by the 100-char test limit)");
}

struct FakeSummarizer;

impl Summarizer for FakeSummarizer {
    fn summarize(&self, prompt: String) -> BoxFuture<'static, Result<String, String>> {
        let lines = prompt.lines().filter(|l| l.starts_with('[') || l.starts_with('（')).count();
        async move { Ok(format!("摘要了 {lines} 行")) }.boxed()
    }
}

#[tokio::test]
async fn long_group_history_is_compressed_in_the_background_and_kept_whole() {
    let runner = Arc::new(FakeRunner::default());
    let home = std::env::temp_dir().join(format!("bulge-hub-compress-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let hub = Hub::new(runner.clone(), Some(Arc::new(FakeSummarizer)), &home, &home.join("ws"), 1).unwrap();
    let channel = FakeChannel::default();
    let access = AccessConfig { open_groups: vec!["Cgroup".into()], ..Default::default() };
    let total = bulge_channels::history::RECENT_KEEP + bulge_channels::history::CHUNK;
    for i in 0..total {
        hub.handle(&channel, &access, group("amy", &format!("訊息 {i}"), false)).await;
    }
    for _ in 0..100 {
        if hub.compacting.lock().unwrap().is_empty() && hub.history.next_compaction("fake:main:Cgroup").unwrap().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    hub.handle(&channel, &access, group("ben", "訊息 3 是什麼", true)).await;
    let goal = runner.runs.lock().unwrap()[0].0.clone();
    assert!(goal.contains(&format!("摘要了 {} 行", bulge_channels::history::CHUNK)), "the digest is in the context");
    assert!(goal.contains("amy: 訊息 3"), "the old message itself is still retrievable");
    assert_eq!(hub.history.recent("fake:main:Cgroup", usize::MAX).unwrap().len(), total + 1, "nothing was deleted");
}

#[cfg(unix)]
#[test]
fn inbox_files_never_go_through_a_symlink() {
    let root = std::env::temp_dir().join(format!("bulge-inbox-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let outside = root.join("outside");
    let workspace = root.join("ws");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(workspace.join("inbox")).unwrap();
    // A dangling link named like an incoming file.
    std::os::unix::fs::symlink(outside.join("planted"), workspace.join("inbox/a.txt")).unwrap();
    assert_eq!(create_new_file(&workspace.join("inbox/a.txt"), b"x").unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    assert!(!outside.join("planted").exists());
    // inbox itself a link to elsewhere.
    std::fs::remove_dir_all(workspace.join("inbox")).unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("inbox")).unwrap();
    assert!(ensure_real_dir(&workspace, &workspace.join("inbox")).unwrap_err().contains("symlink"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_file_alone_waits_for_the_request_and_closed_groups_stay_closed() {
    let runner = Arc::new(FakeRunner::default());
    let hub = hub("files", runner.clone());
    let mut channel = FakeChannel::default();
    channel.files.insert("doc".into(), b"%PDF-1.7".to_vec());
    let access = AccessConfig { allow_from: vec!["owner".into()], ..Default::default() };
    let file = Inbound { attachments: vec![Attachment { kind: "file".into(), name: Some("../../報告 v2.pdf".into()), source: "doc".into(), size: None }], ..message("owner", "") };
    hub.handle(&channel, &access, file).await;
    assert!(runner.runs.lock().unwrap().is_empty());
    assert!(channel.sent.lock().unwrap()[0].1.contains("收到 1 個檔案"));
    hub.handle(&channel, &access, message("owner", "摘要這份報告")).await;
    let runs = runner.runs.lock().unwrap().clone();
    assert!(runs[0].0.contains("- inbox/報告 v2.pdf（檔案"), "{}", runs[0].0);
    assert!(hub.workspace.join("inbox/報告 v2.pdf").exists(), "no path escape");
    // Groups not opened: strangers are ignored and nothing is recorded.
    hub.handle(&channel, &access, group("stranger", "hi", true)).await;
    assert_eq!(runner.runs.lock().unwrap().len(), 1);
    assert!(hub.history.context("fake:main:Cgroup", "hi").unwrap().is_none());
}

#[test]
fn config_defaults_and_secret_permissions() {
    let config: ChannelsConfig = serde_json::from_str(r#"{"workspace":"/tmp/chat","accounts":[{"kind":"telegram","secrets":{"token":"tg"}}]}"#).unwrap();
    assert_eq!(config.autonomy, Autonomy::FullAuto);
    assert!(config.network);
    assert_eq!(config.accounts[0].account, "main");
    assert!(serde_json::from_str::<ChannelsConfig>(r#"{"workspace":"/x","accounts":[],"typo":1}"#).is_err());

    use std::os::unix::fs::PermissionsExt;
    let home = std::env::temp_dir().join(format!("bulge-secret-{}", std::process::id()));
    std::fs::create_dir_all(home.join(".bulge/keys")).unwrap();
    let file = home.join(".bulge/keys/tg");
    std::fs::write(&file, "123:abc\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_secret(&home, "tg").unwrap_err().contains("chmod 600"));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_secret(&home, "tg").unwrap(), "123:abc");
    assert!(read_secret(&home, "../etc/passwd").is_err());
}
