//! Signal through signal-cli's JSON-RPC mode over the child process's stdio:
//! `signal-cli -a <number> --output=json jsonRpc`. No HTTP daemon, no socket,
//! no listening port; signal-cli itself talks to Signal's servers.
//!
//! The account must already be registered or linked in signal-cli (its own
//! data directory holds the keys; bulge never sees them).

use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{Attachment, Channel, ChannelError, Inbound, kind_from_mime};

/// Signal allows ~2000 characters before sending as a long-text attachment,
/// which signal-cli handles; keep to the shared conservative limit.
const TEXT_LIMIT: usize = 4000;
/// How long one `poll` waits for messages before returning an empty batch.
const POLL_SECS: u64 = 30;
/// How long a request (send, typing) waits for signal-cli's answer.
const REQUEST_SECS: u64 = 60;
/// Lines of stderr kept for the error when signal-cli exits.
const STDERR_LINES: usize = 10;
/// A process that lived this long is not "crashing in a loop".
const STABLE_SECS: u64 = 300;
const MAX_RESTART_SECS: u64 = 300;

type Pending = Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>;

/// What the stdout reader shares with the channel.
struct Shared {
    pending: Pending,
    /// Receive notifications' envelopes, normalized at poll time.
    inbox: mpsc::UnboundedSender<Value>,
}

/// One running signal-cli.
struct Process {
    child: Child,
    stdin: ChildStdin,
    started: Instant,
    exited: watch::Receiver<bool>,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
    stderr_task: tokio::task::JoinHandle<()>,
}

pub struct Signal {
    name: String,
    number: String,
    program: String,
    /// Where signal-cli saves received attachments (by attachment id).
    attachments_dir: std::path::PathBuf,
    /// The account's ACI (mentions name users by uuid), when signal-cli told us.
    own_uuid: Mutex<Option<String>>,
    shared: Arc<Shared>,
    inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<Value>>,
    process: tokio::sync::Mutex<Option<Process>>,
    next_id: AtomicU64,
    /// Quick exits in a row, for the restart delay.
    crashes: AtomicU32,
}

impl Signal {
    /// Start signal-cli for `number` (already registered/linked there) and
    /// learn the account's uuid. `signal_cli` is the program to run.
    pub async fn connect(account: &str, number: &str, signal_cli: &str, attachments_dir: &std::path::Path) -> Result<Self, ChannelError> {
        let (tx, rx) = mpsc::unbounded_channel();
        let channel = Self {
            name: format!("signal:{account}"),
            number: number.to_owned(),
            program: signal_cli.to_owned(),
            attachments_dir: attachments_dir.to_path_buf(),
            own_uuid: Mutex::new(None),
            shared: Arc::new(Shared { pending: Mutex::new(HashMap::new()), inbox: tx }),
            inbox: tokio::sync::Mutex::new(rx),
            process: tokio::sync::Mutex::new(None),
            next_id: AtomicU64::new(1),
            crashes: AtomicU32::new(0),
        };
        let process = channel.spawn().map_err(|message| ChannelError::Other { channel: channel.name.clone(), message })?;
        *channel.process.lock().await = Some(process);
        // Best effort: without the uuid, mentions are still matched by number.
        if let Ok(status) = channel.request("getUserStatus", json!({ "recipient": [number] }), Duration::from_secs(15)).await {
            let uuid = status.as_array().and_then(|a| a.first()).and_then(|s| s.get("uuid")).and_then(Value::as_str).filter(|u| !u.is_empty());
            if let (Some(uuid), Ok(mut own)) = (uuid, channel.own_uuid.lock()) {
                *own = Some(uuid.to_owned());
            }
        }
        Ok(channel)
    }

    fn transient(&self, message: String) -> ChannelError {
        ChannelError::Transient { channel: self.name.clone(), message, retry_after_secs: None }
    }

    fn spawn(&self) -> Result<Process, String> {
        let mut child = Command::new(&self.program)
            .args(["-a", &self.number, "--output=json", "jsonRpc"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("cannot start signal-cli ({}): {e}", self.program))?;
        let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
            return Err("signal-cli started without pipes".into());
        };
        let (exit_tx, exited) = watch::channel(false);
        let shared = self.shared.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                shared.handle_line(&line);
            }
            if let Ok(mut pending) = shared.pending.lock() {
                for (_, waiter) in pending.drain() {
                    let _ = waiter.send(Err("signal-cli exited".into()));
                }
            }
            let _ = exit_tx.send(true);
        });
        let stderr_tail = Arc::new(Mutex::new(VecDeque::new()));
        let tail = stderr_tail.clone();
        let stderr_task = tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(mut tail) = tail.lock() {
                    if tail.len() == STDERR_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(line.chars().take(300).collect());
                }
            }
        });
        Ok(Process { child, stdin, started: Instant::now(), exited, stderr_tail, stderr_task })
    }

    /// The running process's exit signal, starting signal-cli if it is not running.
    async fn ensure_running(&self) -> Result<watch::Receiver<bool>, ChannelError> {
        let mut process = self.process.lock().await;
        if let Some(running) = process.as_ref() {
            return Ok(running.exited.clone());
        }
        let started = self.spawn().map_err(|m| self.transient(m))?;
        let exited = started.exited.clone();
        *process = Some(started);
        Ok(exited)
    }

    /// Collect an exited process: its status and stderr tail become the error,
    /// whose retry delay grows while signal-cli keeps dying quickly.
    async fn reap(&self) -> ChannelError {
        let Some(mut process) = self.process.lock().await.take() else {
            return self.transient("signal-cli is not running".into());
        };
        let status = match tokio::time::timeout(Duration::from_secs(2), process.child.wait()).await {
            Ok(Ok(status)) => status.to_string(),
            _ => {
                let _ = process.child.kill().await;
                "closed its output".into()
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut process.stderr_task).await;
        let tail = process.stderr_tail.lock().map(|t| t.iter().cloned().collect::<Vec<_>>().join(" | ")).unwrap_or_default();
        let crashes = if process.started.elapsed() < Duration::from_secs(STABLE_SECS) { self.crashes.fetch_add(1, Ordering::Relaxed) + 1 } else {
            self.crashes.store(1, Ordering::Relaxed);
            1
        };
        let delay = 1u64.checked_shl(crashes.saturating_sub(1).min(16)).unwrap_or(MAX_RESTART_SECS).min(MAX_RESTART_SECS);
        let detail = if tail.is_empty() { String::new() } else { format!(": {tail}") };
        ChannelError::Transient { channel: self.name.clone(), message: format!("signal-cli exited ({status}){detail}; restarting"), retry_after_secs: Some(delay) }
    }

    /// One JSON-RPC request; waits for its response.
    async fn request(&self, method: &str, params: Value, wait: Duration) -> Result<Value, ChannelError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut pending) = self.shared.pending.lock() {
            pending.insert(id, tx);
        }
        let forget = || {
            if let Ok(mut pending) = self.shared.pending.lock() {
                pending.remove(&id);
            }
        };
        let mut line = json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": id }).to_string();
        line.push('\n');
        let mut exited = {
            let mut process = self.process.lock().await;
            let Some(running) = process.as_mut() else {
                forget();
                return Err(self.transient(format!("{method}: signal-cli is not running (it restarts on the next poll)")));
            };
            let written = tokio::time::timeout(Duration::from_secs(10), async {
                running.stdin.write_all(line.as_bytes()).await?;
                running.stdin.flush().await
            })
            .await;
            if !matches!(written, Ok(Ok(()))) {
                forget();
                return Err(self.transient(format!("{method}: signal-cli is not accepting requests")));
            }
            running.exited.clone()
        };
        // The process may die before answering (even before the reader saw
        // this request), so its exit ends the wait too.
        let answer = tokio::select! {
            biased;
            answer = tokio::time::timeout(wait, rx) => Some(answer),
            _ = exited.wait_for(|done| *done) => None,
        };
        match answer {
            Some(Ok(Ok(Ok(result)))) => Ok(result),
            Some(Ok(Ok(Err(message)))) => Err(ChannelError::Other { channel: self.name.clone(), message: format!("{method}: {message}") }),
            Some(Err(_)) => {
                forget();
                Err(self.transient(format!("{method}: no answer from signal-cli in {}s", wait.as_secs())))
            }
            Some(Ok(Err(_))) | None => {
                forget();
                Err(self.transient(format!("{method}: signal-cli exited")))
            }
        }
    }

    /// `group:<id>` → `{"groupId": id}`; anything else is a person.
    fn target(chat_id: &str) -> Value {
        match chat_id.strip_prefix("group:") {
            Some(group) => json!({ "groupId": group }),
            None => json!({ "recipient": [chat_id] }),
        }
    }

    /// Normalize one envelope; `None` for anything that is not a text message
    /// from someone else (receipts, typing, sync messages, reactions).
    fn inbound(&self, envelope: &Value) -> Option<Inbound> {
        let data = envelope.get("dataMessage")?;
        let attachments: Vec<Attachment> = data
            .get("attachments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|a| {
                Some(Attachment {
                    kind: kind_from_mime(a.get("contentType").and_then(Value::as_str).unwrap_or("")).to_owned(),
                    name: a.get("filename").and_then(Value::as_str).map(str::to_owned),
                    source: a.get("id")?.as_str()?.to_owned(),
                    size: a.get("size").and_then(Value::as_u64),
                })
            })
            .collect();
        let message = data.get("message").and_then(Value::as_str).unwrap_or("");
        if message.is_empty() && attachments.is_empty() {
            return None;
        }
        let str_of = |key: &str| envelope.get(key).and_then(Value::as_str).filter(|s| !s.is_empty());
        let own_uuid = self.own_uuid.lock().ok().and_then(|u| u.clone());
        let uuid = str_of("sourceUuid");
        if str_of("sourceNumber") == Some(self.number.as_str()) || (uuid.is_some() && uuid == own_uuid.as_deref()) {
            return None;
        }
        let sender = str_of("sourceNumber").or(uuid).or_else(|| str_of("source"))?;
        let group = data.pointer("/groupInfo/groupId").and_then(Value::as_str);
        let is_group = group.is_some();
        // Mentions are U+FFFC placeholders at UTF-16 offsets in the text.
        let ours: Vec<u64> = data
            .get("mentions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|m| m.get("number").and_then(Value::as_str) == Some(self.number.as_str()) || (own_uuid.is_some() && m.get("uuid").and_then(Value::as_str) == own_uuid.as_deref()))
            .filter_map(|m| m.get("start").and_then(Value::as_u64))
            .collect();
        let mut text = String::with_capacity(message.len());
        let mut offset = 0u64;
        for c in message.chars() {
            if !(c == '\u{fffc}' && ours.contains(&offset)) {
                text.push(c);
            }
            offset += c.len_utf16() as u64;
        }
        Some(Inbound {
            channel: self.name.clone(),
            chat_id: group.map_or_else(|| sender.to_owned(), |g| format!("group:{g}")),
            sender_id: sender.to_owned(),
            sender_name: str_of("sourceName").map_or_else(|| sender.to_owned(), |n| format!("{n} ({sender})")),
            is_group,
            mentioned: !is_group || !ours.is_empty(),
            text: text.trim().to_owned(),
            message_id: data.get("timestamp").or_else(|| envelope.get("timestamp")).and_then(Value::as_u64).map(|t| t.to_string()).unwrap_or_default(),
            attachments,
        })
    }
}

impl Shared {
    /// One line of signal-cli's stdout: a response to one of our requests, or
    /// a notification.
    fn handle_line(&self, line: &str) {
        let Ok(value) = serde_json::from_str::<Value>(line) else { return };
        if value.get("method").and_then(Value::as_str) == Some("receive") {
            if let Some(envelope) = value.pointer("/params/envelope") {
                let _ = self.inbox.send(envelope.clone());
            }
            return;
        }
        let Some(id) = value.get("id").and_then(Value::as_u64) else { return };
        let Some(waiter) = self.pending.lock().ok().and_then(|mut p| p.remove(&id)) else { return };
        let outcome = match value.get("error") {
            Some(error) => Err(error.get("message").and_then(Value::as_str).unwrap_or("request failed").to_owned()),
            None => Ok(value.get("result").cloned().unwrap_or(Value::Null)),
        };
        let _ = waiter.send(outcome);
    }
}

impl Channel for Signal {
    fn name(&self) -> &str {
        &self.name
    }

    fn fetch<'a>(&'a self, attachment: &'a Attachment, max_bytes: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        Box::pin(async move {
            // signal-cli has already downloaded and decrypted it, named by id.
            let other = |message: String| ChannelError::Other { channel: self.name.clone(), message };
            if attachment.source.is_empty() || !attachment.source.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) || attachment.source.starts_with('.') {
                return Err(other("bad attachment id".into()));
            }
            let path = self.attachments_dir.join(&attachment.source);
            let size = tokio::fs::metadata(&path).await.map_err(|e| other(format!("attachment {}: {e}", attachment.source)))?.len();
            if size > max_bytes {
                return Err(other(format!("the file is larger than {} MB", max_bytes / (1024 * 1024))));
            }
            tokio::fs::read(&path).await.map_err(|e| other(format!("attachment {}: {e}", attachment.source)))
        })
    }

    fn text_limit(&self) -> usize {
        TEXT_LIMIT
    }

    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
        Box::pin(async move {
            let mut exited = self.ensure_running().await?;
            let mut inbox = self.inbox.lock().await;
            let first = tokio::select! {
                biased;
                envelope = inbox.recv() => envelope,
                _ = exited.wait_for(|done| *done) => None,
                _ = tokio::time::sleep(Duration::from_secs(POLL_SECS)) => return Ok(Vec::new()),
            };
            let Some(first) = first else {
                drop(inbox);
                return Err(self.reap().await);
            };
            let mut envelopes = vec![first];
            while let Ok(more) = inbox.try_recv() {
                envelopes.push(more);
            }
            Ok(envelopes.iter().filter_map(|e| self.inbound(e)).collect())
        })
    }

    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
        let mut params = Self::target(chat_id);
        params["message"] = json!(text);
        Box::pin(async move { self.request("send", params, Duration::from_secs(REQUEST_SECS)).await.map(|_| ()) })
    }

    fn typing(&self, chat_id: &str) -> BoxFuture<'_, ()> {
        let params = Self::target(chat_id);
        Box::pin(async move {
            let _ = self.request("sendTyping", params, Duration::from_secs(5)).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// A temp dir holding a fake `signal-cli` shell script.
    /// Signal tests run one at a time: a test writing its fake signal-cli
    /// while another forks to start one can leave the fresh script open in
    /// the child for an instant, and executing it then fails with "Text
    /// file busy" (ETXTBSY).
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct Fake {
        dir: PathBuf,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Fake {
        /// `body` runs after the script logs its arguments and start; `$D` is
        /// the temp dir.
        fn new(body: &str) -> Self {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).unwrap();
            let dir = std::env::temp_dir().join(format!("bulge-signal-test-{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>()));
            std::fs::create_dir_all(&dir).unwrap();
            let script = format!("#!/bin/sh\nD='{}'\necho \"$@\" > \"$D/args\"\necho start >> \"$D/starts\"\n{body}\n", dir.display());
            let path = dir.join("signal-cli");
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { dir }
        }

        fn program(&self) -> String {
            self.dir.join("signal-cli").display().to_string()
        }

        fn read(&self, file: &str) -> String {
            std::fs::read_to_string(self.dir.join(file)).unwrap_or_default()
        }
    }

    /// Answers requests by id; after `getUserStatus` emits `notifications`.
    fn serving(notifications: &[Value]) -> String {
        let notes: String = notifications.iter().map(|n| format!("      printf '%s\\n' '{n}'\n")).collect();
        format!(
            r#"while IFS= read -r line; do
  echo "$line" >> "$D/requests"
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *getUserStatus*)
      printf '{{"jsonrpc":"2.0","result":[{{"number":"+100","uuid":"bot-uuid","isRegistered":true}}],"id":%s}}\n' "$id"
{notes}      ;;
    *'"recipient":["+404"]'*) printf '{{"jsonrpc":"2.0","error":{{"code":-1,"message":"Unregistered user"}},"id":%s}}\n' "$id" ;;
    *) printf '{{"jsonrpc":"2.0","result":{{"timestamp":1}},"id":%s}}\n' "$id" ;;
  esac
done"#
        )
    }

    fn receive(envelope: Value) -> Value {
        json!({ "jsonrpc": "2.0", "method": "receive", "params": { "envelope": envelope, "account": "+100" } })
    }

    #[tokio::test]
    async fn receives_dms_groups_and_mentions() {
        let _serial = SERIAL.lock().await;
        let notes = [
            receive(json!({ "source": "+200", "sourceNumber": "+200", "sourceUuid": "u-200", "sourceName": "Owner", "timestamp": 11, "dataMessage": { "timestamp": 11, "message": "幫我整理報告" } })),
            receive(json!({ "sourceNumber": null, "sourceUuid": "u-300", "sourceName": "A", "timestamp": 12, "dataMessage": { "timestamp": 12, "message": "\u{fffc} summarize this", "mentions": [{ "uuid": "bot-uuid", "start": 0, "length": 1 }], "groupInfo": { "groupId": "G1==", "type": "DELIVER" } } })),
            receive(json!({ "sourceNumber": "+300", "sourceUuid": "u-300", "timestamp": 13, "dataMessage": { "timestamp": 13, "message": "just chatting \u{fffc}", "mentions": [{ "uuid": "u-999", "start": 14, "length": 1 }], "groupInfo": { "groupId": "G1==" } } })),
            receive(json!({ "sourceNumber": "+300", "timestamp": 14, "dataMessage": { "timestamp": 14, "message": "by number \u{fffc}", "mentions": [{ "number": "+100", "start": 10, "length": 1 }], "groupInfo": { "groupId": "G1==" } } })),
            receive(json!({ "sourceNumber": "+200", "timestamp": 15, "receiptMessage": { "isDelivery": true } })),
            receive(json!({ "sourceNumber": "+200", "timestamp": 16, "typingMessage": { "action": "STARTED" } })),
        ];
        let fake = Fake::new(&serving(&notes));
        let signal = Signal::connect("main", "+100", &fake.program(), std::path::Path::new("/nonexistent")).await.unwrap();
        assert_eq!(fake.read("args").trim(), "-a +100 --output=json jsonRpc");
        let mut batch = Vec::new();
        while batch.len() < 4 {
            batch.extend(signal.poll().await.unwrap());
        }
        assert_eq!(batch.len(), 4, "receipts and typing are skipped: {batch:?}");
        let dm = &batch[0];
        assert_eq!((dm.chat_id.as_str(), dm.sender_id.as_str(), dm.sender_name.as_str(), dm.text.as_str(), dm.message_id.as_str()), ("+200", "+200", "Owner (+200)", "幫我整理報告", "11"));
        assert!(!dm.is_group && dm.mentioned);
        assert_eq!(dm.channel, "signal:main");
        assert_eq!((batch[1].chat_id.as_str(), batch[1].sender_id.as_str(), batch[1].is_group, batch[1].mentioned, batch[1].text.as_str()), ("group:G1==", "u-300", true, true, "summarize this"));
        assert!(batch[2].is_group && !batch[2].mentioned, "someone else was mentioned");
        assert!(batch[3].mentioned && batch[3].text == "by number", "mentioned by number");
    }

    #[tokio::test]
    async fn sends_requests_and_reads_responses() {
        let _serial = SERIAL.lock().await;
        let fake = Fake::new(&serving(&[]));
        let signal = Signal::connect("main", "+100", &fake.program(), std::path::Path::new("/nonexistent")).await.unwrap();
        signal.send("+200", "hello").await.unwrap();
        signal.send("group:G1==", "大家好").await.unwrap();
        signal.typing("+200").await;
        let error = signal.send("+404", "hi").await.unwrap_err();
        assert!(!error.is_fatal() && error.to_string().contains("Unregistered user"), "{error}");
        let requests: Vec<Value> = fake.read("requests").lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let methods: Vec<&str> = requests.iter().map(|r| r["method"].as_str().unwrap()).collect();
        assert_eq!(methods, ["getUserStatus", "send", "send", "sendTyping", "send"]);
        assert_eq!(requests[1]["params"], json!({ "recipient": ["+200"], "message": "hello" }));
        assert_eq!(requests[2]["params"], json!({ "groupId": "G1==", "message": "大家好" }));
        assert_eq!(requests[3]["params"], json!({ "recipient": ["+200"] }));
        let ids: std::collections::HashSet<u64> = requests.iter().map(|r| r["id"].as_u64().unwrap()).collect();
        assert_eq!(ids.len(), requests.len(), "request ids are unique");
        assert!(requests.iter().all(|r| r["jsonrpc"] == "2.0"));
    }

    #[tokio::test]
    async fn process_exit_is_transient_with_stderr_and_restarts() {
        let _serial = SERIAL.lock().await;
        let fake = Fake::new("echo 'User +100 is not registered.' >&2\nexit 3");
        let signal = Signal::connect("main", "+100", &fake.program(), std::path::Path::new("/nonexistent")).await.unwrap();
        match signal.poll().await {
            Err(ChannelError::Transient { message, retry_after_secs: Some(1), .. }) => {
                assert!(message.contains("not registered") && message.contains('3'), "{message}");
            }
            other => panic!("{other:?}"),
        }
        let error = signal.send("+200", "hi").await.unwrap_err();
        assert!(matches!(error, ChannelError::Transient { .. }), "{error:?}");
        match signal.poll().await {
            Err(ChannelError::Transient { retry_after_secs: Some(2), .. }) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.read("starts").lines().count(), 2, "restarted on the next poll");
    }

    #[tokio::test]
    async fn a_missing_program_fails_to_connect() {
        let _serial = SERIAL.lock().await;
        let Err(error) = Signal::connect("main", "+100", "/nonexistent/signal-cli", std::path::Path::new("/nonexistent")).await else { panic!("must fail") };
        assert!(error.to_string().contains("cannot start signal-cli"), "{error}");
    }

    #[tokio::test]
    async fn attachments_are_read_from_signal_clis_folder() {
        let _serial = SERIAL.lock().await;
        let dir = std::env::temp_dir().join(format!("bulge-signal-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("AbC123.jpg"), b"\xFF\xD8\xFF photo").unwrap();
        let notes = [receive(json!({ "sourceNumber": "+200", "timestamp": 21, "dataMessage": { "timestamp": 21, "message": null,
            "attachments": [{ "contentType": "image/jpeg", "filename": "IMG_1.jpg", "id": "AbC123.jpg", "size": 10 }] } }))];
        let fake = Fake::new(&serving(&notes));
        let signal = Signal::connect("main", "+100", &fake.program(), &dir).await.unwrap();
        let mut batch = Vec::new();
        while batch.is_empty() {
            batch.extend(signal.poll().await.unwrap());
        }
        let file = &batch[0].attachments[0];
        assert_eq!((file.kind.as_str(), file.name.as_deref(), batch[0].text.as_str()), ("image", Some("IMG_1.jpg"), ""));
        assert_eq!(signal.fetch(file, 1024).await.unwrap(), b"\xFF\xD8\xFF photo");
        assert!(signal.fetch(file, 4).await.is_err(), "size cap");
        let escape = Attachment { kind: "file".into(), name: None, source: "../../etc/passwd".into(), size: None };
        assert!(signal.fetch(&escape, 1024).await.is_err(), "no path escape");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
