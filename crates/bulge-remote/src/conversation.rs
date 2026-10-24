//! A device's conversation with one host, as a background task: connects
//! through the relay, reconnects with backoff, queues messages typed while
//! offline, acknowledges replies (showing each once), and moves the session
//! to a direct path when hole punching works. Front ends (the CLI, the
//! Android app) only send text in and read [`Event`]s out.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::Failure;
use crate::device::{self, KnownHost, Session};
use crate::direct::{self, Prepared};
use crate::wire::{MAX_MESSAGE_BYTES, Wire};

const STEP: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Connected (again); `direct` once the session moved off the relay.
    Connected { direct: bool },
    Reply(String),
    /// A message was not sent (too long): say so; nothing else changes.
    NotSent(String),
    /// The commands bulge understands (sent when a session starts).
    Commands(Vec<crate::wire::CommandEntry>),
    /// bulge is working on a message.
    Typing,
    /// The connection dropped; reconnecting.
    Disconnected(String),
    /// The host refused this device (revoked, or keys no longer match);
    /// the conversation has stopped.
    Fatal(String),
}

pub struct Conversation {
    /// Messages for bulge. Dropping it does not stop the conversation;
    /// dropping `events` does.
    pub send: mpsc::UnboundedSender<String>,
    pub events: mpsc::Receiver<Event>,
}

/// Start talking to `host`.
pub fn start(dir: PathBuf, host: KnownHost) -> Conversation {
    let (send, input) = mpsc::unbounded_channel();
    let (events_tx, events) = mpsc::channel(64);
    tokio::spawn(run(dir, host, input, events_tx));
    Conversation { send, events }
}

/// Silence in a row after which the host is taken to refuse this device.
const SILENT_LIMIT: u32 = 3;

async fn run(dir: PathBuf, host: KnownHost, input: mpsc::UnboundedReceiver<String>, events: mpsc::Sender<Event>) {
    let mut state = State { input, input_open: true, outbox: VecDeque::new(), last_id: 0 };
    // The newest reply shown, so replies re-sent after a reconnect are not shown twice.
    let mut seen = 0u64;
    let mut backoff = 1u64;
    let mut silent = 0u32;
    loop {
        let failure = match device::connect(&dir, &host).await {
            Ok(session) => Ok(session),
            Err(Failure::Rejected(error)) => {
                let _ = events.send(Event::Fatal(error)).await;
                return;
            }
            Err(Failure::Silent(error)) => {
                silent += 1;
                if silent >= SILENT_LIMIT {
                    let _ = events.send(Event::Fatal(format!("{error} — {silent} times in a row"))).await;
                    return;
                }
                Err(error)
            }
            Err(Failure::Transient(error)) => Err(error),
        };
        let mut session = match failure {
            Ok(mut session) => {
                backoff = 1;
                silent = 0;
                session.resume_after(seen);
                session
            }
            Err(error) => {
                if events.send(Event::Disconnected(format!("{error}; retrying in {backoff}s"))).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
                continue;
            }
        };
        if events.send(Event::Connected { direct: false }).await.is_err() {
            return;
        }
        let lost = serve(&dir, &host, &mut session, &mut state, &events).await;
        seen = seen.max(lost.seen);
        match lost.reason {
            End::Fatal(error) => {
                let _ = events.send(Event::Fatal(error)).await;
                return;
            }
            End::Closed => return,
            End::Lost(error) => {
                if events.send(Event::Disconnected(error)).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

enum End {
    /// The front end went away.
    Closed,
    Lost(String),
    Fatal(String),
}

struct Lost {
    reason: End,
    seen: u64,
}

/// What outlives one connection.
struct State {
    input: mpsc::UnboundedReceiver<String>,
    input_open: bool,
    /// Messages not yet confirmed by the host (re-sent after a reconnect).
    outbox: VecDeque<(u64, String)>,
    /// The newest message number used.
    last_id: u64,
}

/// Await an optional one-shot; never completes when there is none.
async fn pending_or<T>(slot: &mut Option<oneshot::Receiver<T>>) -> Result<T, oneshot::error::RecvError> {
    match slot.as_mut() {
        Some(rx) => rx.await,
        None => std::future::pending().await,
    }
}

/// One connection's worth of conversation (including a possible move to a
/// direct path, which replaces `session`).
async fn serve(dir: &std::path::Path, host: &KnownHost, session: &mut Session, state: &mut State, events: &mpsc::Sender<Event>) -> Lost {
    let State { input, input_open, outbox, last_id } = state;
    let lost = |session: &Session, reason: End| Lost { reason, seen: session.seen() };
    for (id, text) in outbox.iter() {
        if let Err(error) = session.send(&Wire::Msg { id: *id, text: text.clone() }).await {
            return lost(session, End::Lost(error));
        }
    }
    // Ask for a direct path once the socket knows its public address.
    let (prepared_tx, prepared_rx) = oneshot::channel();
    let relay = host.relay.clone();
    tokio::spawn(async move {
        let _ = prepared_tx.send(direct::prepare(&relay, STEP).await);
    });
    let mut preparing = Some(prepared_rx);
    let mut prepared: Option<Prepared> = None;
    let mut upgrading: Option<oneshot::Receiver<Result<Session, Failure>>> = None;
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.tick().await;
    loop {
        tokio::select! {
            () = events.closed() => return lost(session, End::Closed),
            text = input.recv(), if *input_open => match text {
                Some(text) if text.len() > MAX_MESSAGE_BYTES => {
                    let _ = events.send(Event::NotSent(format!("訊息太長（{} KB），上限約 {} KB；請分段或改傳檔案。", text.len() / 1024, MAX_MESSAGE_BYTES / 1024))).await;
                }
                Some(text) => {
                    // Numbered from the clock, so numbers keep growing across restarts.
                    *last_id = (*last_id + 1).max(bulge_util::now_ms());
                    outbox.push_back((*last_id, text.clone()));
                    if let Err(error) = session.send(&Wire::Msg { id: *last_id, text }).await {
                        return lost(session, End::Lost(error));
                    }
                }
                None => *input_open = false,
            },
            message = session.next() => match message {
                Ok(Some(Wire::Reply { text, .. })) => {
                    if events.send(Event::Reply(text)).await.is_err() {
                        return lost(session, End::Closed);
                    }
                }
                Ok(Some(Wire::Typing)) => {
                    let _ = events.send(Event::Typing).await;
                }
                Ok(Some(Wire::Received { id })) => outbox.retain(|(queued, _)| *queued > id),
                Ok(Some(Wire::Unknown)) => {}
                Ok(Some(Wire::Commands { list })) => {
                    let _ = events.send(Event::Commands(list)).await;
                }
                Ok(Some(Wire::Punch { candidates, cert: Some(cert) })) => {
                    if let Some(prepared) = prepared.take() {
                        let (tx, rx) = oneshot::channel();
                        let (dir, host) = (dir.to_path_buf(), host.clone());
                        tokio::spawn(async move {
                            let result = async {
                                let link = direct::dial(prepared, direct::parse_candidates(&candidates), &cert, STEP).await?;
                                device::connect_over(&dir, &host, link).await
                            };
                            let _ = tx.send(result.await);
                        });
                        upgrading = Some(rx);
                    }
                }
                Ok(Some(Wire::Error { message })) => return lost(session, End::Fatal(format!("bulge: {message}"))),
                Ok(Some(Wire::Pong)) => {}
                Ok(Some(other)) => return lost(session, End::Lost(format!("unexpected {other:?}"))),
                Ok(None) => return lost(session, End::Lost("connection closed".into())),
                Err(error) => return lost(session, End::Lost(error)),
            },
            ready = pending_or(&mut preparing), if preparing.is_some() => {
                preparing = None;
                if let Ok(Ok(ready)) = ready {
                    let candidates = ready.candidates.iter().map(ToString::to_string).collect();
                    if let Err(error) = session.send(&Wire::Punch { candidates, cert: None }).await {
                        return lost(session, End::Lost(error));
                    }
                    prepared = Some(ready);
                }
            },
            moved = pending_or(&mut upgrading), if upgrading.is_some() => {
                upgrading = None;
                if let Ok(Ok(mut direct)) = moved {
                    direct.resume_after(session.seen());
                    *session = direct;
                    let _ = events.send(Event::Connected { direct: true }).await;
                }
            },
            _ = ping.tick() => {
                if let Err(error) = session.send(&Wire::Ping).await {
                    return lost(session, End::Lost(error));
                }
            }
        }
    }
}
