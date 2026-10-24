//! The slot server: runs commands inside one slot.

use std::io;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use bulge_proto::msg::Outcome;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use crate::runtime::{CommandRuntime, Invocation};
use super::{SlotResponse, parse_slot_request, validate_slot};

pub(crate) static NEXT_INVOCATION_ID: AtomicU64 = AtomicU64::new(1);

#[allow(unsafe_code)] // adopting the inherited listener on fd 3 (see SAFETY below)
pub async fn slot_server_main(slot: u8) -> Result<(), String> {
    validate_slot(slot)?;
    if let Ok(proxy) = std::env::var("BULGE_EGRESS_PROXY")
        && !proxy.is_empty()
    {
        let _ = crate::EGRESS_PROXY.set(proxy);
        // This slot has its own network namespace: serve its loopback proxy
        // address by relaying to the main bridge's unix socket.
        tokio::spawn(async {
            if let Err(error) = crate::bridge::relay_to_unix().await {
                eprintln!("sandboxd: slot egress relay: {error}");
            }
        });
    }

    let runtime = CommandRuntime::builder()
        .command("exec", crate::commands::exec)
        .command("read", crate::tools::handlers::read)
        .command("write", crate::tools::handlers::write)
        .command("edit", crate::tools::handlers::edit)
        .command("glob", crate::tools::handlers::glob)
        .command("grep", crate::tools::handlers::grep)
        .max_timeout(Duration::from_secs(30 * 60))
        .build()
        .map_err(|e| format!("slot runtime: {e}"))?;

    // SAFETY: the privileged helper duped the already-bound listening socket to
    // fd 3 before exec and cleared CLOEXEC.
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    listener.set_nonblocking(true).map_err(|e| format!("slot listener: {e}"))?;
    let listener = tokio::net::UnixListener::from_std(listener).map_err(|e| format!("slot listener: {e}"))?;
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("sandboxd: slot {slot} accept: {error}");
                continue;
            }
        };
        let runtime = runtime.clone();
        tokio::spawn(async move {
            serve_connection(stream, runtime).await;
        });
    }
}

pub(crate) async fn serve_connection(stream: tokio::net::UnixStream, runtime: CommandRuntime) {
    let (read_half, write_half) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(write_half));
    let mut reader = TokioBufReader::new(read_half);
    let active: Arc<Mutex<std::collections::HashSet<u64>>> = Arc::new(Mutex::new(std::collections::HashSet::new()));

    loop {
        let mut line = String::new();
        let read = match reader.read_line(&mut line).await {
            Ok(read) => read,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let request = match parse_slot_request(&line) {
            Ok(request) => request,
            Err(message) => {
                let response = SlotResponse {
                    id: 0,
                    outcome: Outcome::Err {
                        code: "INVALID_PARAMS".into(),
                        message,
                    },
                };
                let _ = write_response(&writer, &response).await;
                continue;
            }
        };
        let internal_id = NEXT_INVOCATION_ID.fetch_add(1, Ordering::Relaxed);
        active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(internal_id);
        let runtime = runtime.clone();
        let writer = writer.clone();
        let active = active.clone();
        tokio::spawn(async move {
            let invocation = Invocation {
                id: internal_id,
                command: request.command,
                params: request.params,
                timeout: request.timeout_ms.map(Duration::from_millis),
            };
            let outcome = runtime.evaluate(invocation).await;
            active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&internal_id);
            let response = SlotResponse {
                id: request.id,
                outcome,
            };
            let _ = write_response(&writer, &response).await;
        });
    }

    // A closed connection cancels every request still in flight on it.
    let in_flight: Vec<u64> = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .collect();
    for id in in_flight {
        runtime.cancel(id);
    }
}

pub(crate) async fn write_response(writer: &Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>, response: &SlotResponse) -> io::Result<()> {
    let mut line = serde_json::to_string(response).map_err(io::Error::other)?;
    line.push('\n');
    let mut writer = writer.lock().await;
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}
