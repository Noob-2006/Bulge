//! sandboxd: PID-1 payload of the bulge guest.
//!
//! 1. Read the one-shot bootstrap (session key) and lock the filesystem down.
//! 2. Listen on the control vsock port, accept the host, run the handshake.
//! 3. Serve invocations through the bounded command runtime until shutdown.

use std::time::Duration;

use bulge_proto::frame::{PeerRole, SessionKey};
use bulge_proto::msg::{BOOTSTRAP_PATH, Bootstrap, CONTROL_VSOCK_PORT, GuestMessage, HostMessage};
use bulge_proto::session::{SessionParams, establish};
use sandboxd::{commands, tools};
use sandboxd::runtime::{CommandRuntime, Invocation};
use tokio::sync::mpsc;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

#[tokio::main]
async fn main() {
    if let Err(message) = run().await {
        eprintln!("sandboxd: {message}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let bootstrap = read_bootstrap()?;
    // Pick the unprivileged id to run as. If the host runs bulge as root we have
    // no matching non-root owner, so fall back to `nobody`.
    let (uid, gid) = target_ids(bootstrap.host_uid, bootstrap.host_gid);
    sandboxd::setup::lock_down(uid, gid).map_err(|e| format!("setup: {e}"))?;
    sandboxd::setup::drop_privileges(uid, gid).map_err(|e| format!("drop privileges: {e}"))?;

    // Start the egress bridge if the host armed the gateway (both secrets present).
    // Tools reach the outside world only through it; otherwise the guest is
    // air-gapped.
    if !bootstrap.gateway_token.is_empty() && !bootstrap.gateway_key.is_empty() {
        let _ = sandboxd::EGRESS_PROXY.set(sandboxd::bridge::PROXY_URL.to_string());
        let (token, key) = (bootstrap.gateway_token.clone(), bootstrap.gateway_key.clone());
        tokio::spawn(async move {
            let _ = sandboxd::bridge::serve(token, key).await;
        });
    }

    let runtime = CommandRuntime::builder()
        .command("ping", |_| async { Ok(serde_json::json!("pong")) })
        .command("exec", commands::exec)
        .command("changes", commands::changes)
        .command("export_changes", tools::handlers::export_changes)
        .command("read", tools::handlers::read)
        .command("write", tools::handlers::write)
        .command("edit", tools::handlers::edit)
        .command("glob", tools::handlers::glob)
        .command("grep", tools::handlers::grep)
        .max_timeout(Duration::from_secs(30 * 60))
        .build()
        .map_err(|e| format!("runtime: {e}"))?;

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, CONTROL_VSOCK_PORT)).map_err(|e| format!("vsock bind: {e}"))?;
    let (stream, _) = listener.accept().await.map_err(|e| format!("vsock accept: {e}"))?;
    drop(listener);

    let params = SessionParams {
        key: bootstrap.key,
        session_id: bootstrap.session_id,
        generation: bootstrap.generation,
        name: "sandboxd".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        artifact_identity: concat!("sandboxd-", env!("CARGO_PKG_VERSION")).into(),
    };
    let (mut tx, mut rx, _) = establish(stream, PeerRole::Guest, params).await.map_err(|e| format!("handshake: {e}"))?;
    tx.send(&GuestMessage::Ready { commands: runtime.command_names() }).await.map_err(|e| format!("send: {e}"))?;

    // One writer task owns the sender; handlers report results through it.
    let (results, mut pending) = mpsc::channel::<GuestMessage>(64);
    let writer = tokio::spawn(async move {
        while let Some(message) = pending.recv().await {
            if tx.send(&message).await.is_err() {
                break;
            }
        }
    });

    loop {
        let message: HostMessage = match rx.recv().await {
            Ok(message) => message,
            Err(_) => break, // host gone or channel poisoned: stop everything
        };
        match message {
            HostMessage::Invoke { id, command, params, timeout_ms } => {
                let runtime = runtime.clone();
                let results = results.clone();
                tokio::spawn(async move {
                    let invocation = Invocation { id, command, params, timeout: timeout_ms.map(Duration::from_millis) };
                    let outcome = runtime.evaluate(invocation).await;
                    let _ = results.send(GuestMessage::Result { id, outcome }).await;
                });
            }
            HostMessage::Cancel { id } => runtime.cancel(id),
            HostMessage::Shutdown => break,
        }
    }
    runtime.cancel_all();
    drop(results);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    Ok(())
}

/// The unprivileged id to run as: the host owner, or `nobody` (65534) when the
/// host runs as root (uid 0) and there is no non-root owner to match.
fn target_ids(host_uid: u32, host_gid: u32) -> (u32, u32) {
    const NOBODY: u32 = 65534;
    let uid = if host_uid == 0 { NOBODY } else { host_uid };
    let gid = if host_gid == 0 { NOBODY } else { host_gid };
    (uid, gid)
}

/// Everything the guest needs from the one-shot bootstrap file.
struct BootstrapInfo {
    key: SessionKey,
    session_id: String,
    generation: u64,
    host_uid: u32,
    host_gid: u32,
    gateway_token: String,
    gateway_key: String,
}

/// Read the one-shot bootstrap (a second read fails).
fn read_bootstrap() -> Result<BootstrapInfo, String> {
    let raw = std::fs::read_to_string(BOOTSTRAP_PATH).map_err(|e| format!("bootstrap: {e}"))?;
    let bootstrap: Bootstrap = serde_json::from_str(&raw).map_err(|e| format!("bootstrap: {e}"))?;
    let hex = bootstrap.session_key_hex.as_bytes();
    if hex.len() != 64 {
        return Err("bootstrap: session key must be 32 bytes".into());
    }
    let mut key = [0u8; 32];
    for (i, pair) in hex.chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| "bootstrap: bad hex")?;
        key[i] = u8::from_str_radix(text, 16).map_err(|_| "bootstrap: bad hex")?;
    }
    Ok(BootstrapInfo {
        key: SessionKey::from_bytes(key),
        session_id: bootstrap.session_id,
        generation: bootstrap.generation,
        host_uid: bootstrap.host_uid,
        host_gid: bootstrap.host_gid,
        gateway_token: bootstrap.gateway_token,
        gateway_key: bootstrap.gateway_key,
    })
}
