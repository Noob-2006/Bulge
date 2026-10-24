//! The encrypted link between a host or device and the relay:
//! `Noise_NK_25519_ChaChaPoly_BLAKE2s`, pinned to the relay's static key.
//!
//! Everything sent to the relay goes through it — control frames (host ids,
//! session ids) as well as the device↔host traffic, which is already Noise
//! ciphertext end to end — so someone watching the network sees neither who
//! is talking to whom nor any content. The relay's key travels in the host's
//! configuration and the pairing link; a relay that cannot prove it holds
//! that key fails the handshake. There is no unencrypted mode.

use std::sync::Arc;
use std::time::Duration;

use snow::StatelessTransportState;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::frame::{Duplex, MAX_FRAME, read_frame, spawn_reader, write_frame};
use crate::noise::Keypair;

pub const PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"bulge-relay/2";
const TAG: usize = 16;
/// The largest frame a tunnel carries.
pub const MAX_PAYLOAD: usize = MAX_FRAME - TAG;

fn builder() -> Result<snow::Builder<'static>, String> {
    Ok(snow::Builder::new(PATTERN.parse().map_err(|e| format!("noise params: {e:?}"))?))
}

/// Dial the relay at `addr` and run the handshake against its pinned key.
pub async fn connect(addr: &str, relay_key: &[u8; 32], step: Duration) -> Result<Duplex, crate::Failure> {
    let stream = timeout(step, TcpStream::connect(addr)).await.map_err(|_| format!("relay {addr} did not answer"))?.map_err(|e| format!("relay {addr}: {e}"))?;
    let _ = stream.set_nodelay(true);
    let mut handshake = builder()?
        .remote_public_key(relay_key)
        .and_then(|b| b.prologue(PROLOGUE))
        .and_then(snow::Builder::build_initiator)
        .map_err(|e| format!("noise: {e}"))?;
    let (mut read, mut write) = stream.into_split();
    let mut buf = vec![0u8; MAX_FRAME];
    let len = handshake.write_message(&[], &mut buf).map_err(|e| format!("noise: {e}"))?;
    write_frame(&mut write, &buf[..len]).await?;
    let reply = timeout(step, read_frame(&mut read, MAX_FRAME)).await.map_err(|_| format!("relay {addr} did not finish the handshake"))??;
    handshake.read_message(&reply, &mut buf).map_err(|_| crate::Failure::Rejected(format!("relay {addr} is not the relay this bulge is pinned to (key mismatch)")))?;
    let state = handshake.into_stateless_transport_mode().map_err(|e| format!("noise: {e}"))?;
    Ok(run(read, write, state))
}

/// Relay side: answer a client's handshake with the relay's static key.
pub async fn accept(stream: TcpStream, keys: &Keypair, step: Duration) -> Result<Duplex, String> {
    let _ = stream.set_nodelay(true);
    let mut handshake = builder()?
        .local_private_key(keys.private.as_slice())
        .and_then(|b| b.prologue(PROLOGUE))
        .and_then(snow::Builder::build_responder)
        .map_err(|e| format!("noise: {e}"))?;
    let (mut read, mut write) = stream.into_split();
    let first = timeout(step, read_frame(&mut read, MAX_FRAME)).await.map_err(|_| "no handshake".to_string())??;
    let mut buf = vec![0u8; MAX_FRAME];
    handshake.read_message(&first, &mut buf).map_err(|_| "handshake failed".to_string())?;
    let len = handshake.write_message(&[], &mut buf).map_err(|e| format!("noise: {e}"))?;
    write_frame(&mut write, &buf[..len]).await?;
    let state = handshake.into_stateless_transport_mode().map_err(|e| format!("noise: {e}"))?;
    Ok(run(read, write, state))
}

/// Encrypt outgoing frames and decrypt incoming ones on their own tasks,
/// each direction with its own nonce counter.
fn run(read: tokio::net::tcp::OwnedReadHalf, mut write: tokio::net::tcp::OwnedWriteHalf, state: StatelessTransportState) -> Duplex {
    let state = Arc::new(state);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);
    let writer_state = state.clone();
    tokio::spawn(async move {
        let mut nonce = 0u64;
        let mut buf = vec![0u8; MAX_FRAME];
        while let Some(plain) = out_rx.recv().await {
            let Ok(len) = writer_state.write_message(nonce, &plain, &mut buf) else { return };
            nonce += 1;
            if write_frame(&mut write, &buf[..len]).await.is_err() {
                return;
            }
        }
    });
    let mut raw = spawn_reader(read, MAX_FRAME);
    let (in_tx, in_rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut nonce = 0u64;
        let mut buf = vec![0u8; MAX_FRAME];
        while let Some(frame) = raw.recv().await {
            let plain = frame.and_then(|cipher| {
                let len = state.read_message(nonce, &cipher, &mut buf).map_err(|_| "a relay frame failed to decrypt".to_string())?;
                nonce += 1;
                Ok(buf[..len].to_vec())
            });
            let failed = plain.is_err();
            if in_tx.send(plain).await.is_err() || failed {
                return;
            }
        }
    });
    Duplex::new(out_tx, in_rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::generate_keypair;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn frames_cross_encrypted_and_a_wrong_pin_fails() {
        let keys = generate_keypair().unwrap();
        let public = keys.public;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = accept(stream, &keys, Duration::from_secs(5)).await.unwrap();
            let got = link.recv().await.unwrap().unwrap();
            link.send([got.as_slice(), b" back"].concat()).await.unwrap();
            // The wrong-pin client's handshake fails on our side too.
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, &keys, Duration::from_secs(5)).await.ok();
        });
        let mut link = connect(&addr, &public, Duration::from_secs(5)).await.unwrap();
        link.send(b"ping".to_vec()).await.unwrap();
        assert_eq!(link.recv().await.unwrap().unwrap(), b"ping back");
        let wrong = generate_keypair().unwrap().public;
        assert!(connect(&addr, &wrong, Duration::from_secs(5)).await.is_err());
        server.await.unwrap();
    }
}
