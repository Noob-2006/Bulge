//! sandboxd: PID-1 payload of the bulge guest.
//!
//! 1. Read the one-shot bootstrap (session key) and lock the filesystem down.
//! 2. Listen on the control vsock port, accept the host, run the handshake.
//! 3. Serve invocations through the bounded command runtime until shutdown.

use std::time::Duration;

use bulge_proto::frame::{PeerRole, SessionKey};
use bulge_proto::msg::{BOOTSTRAP_PATH, Bootstrap, CONTROL_VSOCK_PORT, GuestMessage, HostMessage};
use bulge_proto::session::{SessionParams, establish};
use sandboxd::runtime::{CommandRuntime, Invocation};
use sandboxd::{commands, slots, tools};
use tokio::sync::mpsc;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

fn main() {
    let mut args = std::env::args();
    let _program = args.next();
    match args.next().as_deref() {
        Some("--slot-helper") => {
            if let Err(message) = slots::helper_main() {
                eprintln!("sandboxd: slot helper: {message}");
                std::process::exit(1);
            }
        }
        Some("--slot-holder") => {
            let slot = args.next().and_then(|slot| slot.parse::<u8>().ok());
            let Some(slot) = slot else {
                eprintln!("sandboxd: --slot-holder needs a slot number");
                std::process::exit(2);
            };
            if let Err(message) = slots::holder_main(slot) {
                eprintln!("sandboxd: slot holder: {message}");
                std::process::exit(1);
            }
        }
        Some("--slot-server") => {
            let Some(slot) = args.next() else {
                eprintln!("sandboxd: --slot-server needs a slot number");
                std::process::exit(2);
            };
            let slot: u8 = match slot.parse() {
                Ok(slot) => slot,
                Err(error) => {
                    eprintln!("sandboxd: invalid slot {slot}: {error}");
                    std::process::exit(2);
                }
            };
            let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("sandboxd: tokio: {error}");
                    std::process::exit(2);
                }
            };
            if let Err(message) = runtime.block_on(slots::slot_server_main(slot)) {
                eprintln!("sandboxd: slot server: {message}");
                std::process::exit(1);
            }
        }
        _ => {
            let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("sandboxd: tokio: {error}");
                    std::process::exit(2);
                }
            };
            if let Err(message) = runtime.block_on(run()) {
                eprintln!("sandboxd: {message}");
                std::process::exit(1);
            }
        }
    }
}

async fn run() -> Result<(), String> {
    let bootstrap = read_bootstrap()?;
    // Pick the unprivileged id to run as. If the host runs bulge as root we have
    // no matching non-root owner, so fall back to `nobody`.
    let (uid, gid) = target_ids(bootstrap.host_uid, bootstrap.host_gid);
    sandboxd::setup::lock_down(uid, gid).map_err(|e| format!("setup: {e}"))?;

    // The helper needs the egress URL before it starts, and it must be started
    // before we drop privileges (it does all root-only slot setup).
    let egress_proxy = if !bootstrap.gateway_token.is_empty() && !bootstrap.gateway_key.is_empty() {
        Some(sandboxd::bridge::PROXY_URL)
    } else {
        None
    };
    if let Some(proxy) = egress_proxy {
        let _ = sandboxd::EGRESS_PROXY.set(proxy.to_string());
    }
    let helper = slots::HelperClient::spawn(uid, gid, egress_proxy).map_err(|e| format!("slot helper: {e}"))?;
    slots::install_helper(helper)?;
    sandboxd::setup::drop_privileges(uid, gid).map_err(|e| format!("drop privileges: {e}"))?;

    // Start the egress bridge if the host armed the gateway (both secrets present).
    // Tools reach the outside world only through it; otherwise the guest is
    // air-gapped.
    if egress_proxy.is_some() {
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
        .command("view_image", tools::handlers::view_image)
        .command("browser", sandboxd::browser::browser)
        .command("slot_open", slots::slot_open)
        .command("slot_changes", slots::slot_changes)
        .command("slot_export", slots::slot_export)
        .command("slot_merge", slots::slot_merge)
        .command("slot_stage", slots::slot_stage)
        .command("slot_close", slots::slot_close)
        .command("slot_run", slots::slot_run)
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
