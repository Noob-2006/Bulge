//! Direct device↔host connections: UDP hole punching, then QUIC.
//!
//! Negotiated inside an already authenticated end-to-end session over the
//! relay, so nothing here is trusted on its own:
//!
//! 1. Each side binds a UDP socket and asks the relay's STUN responder which
//!    public address that socket appears as ([`prepare`]).
//! 2. The device sends its candidate addresses (`Wire::Punch`); the host
//!    answers with its own and the SHA-256 fingerprint of a fresh, throwaway
//!    QUIC certificate ([`listen`]), then sends a few datagrams to each of
//!    the device's candidates so its NAT lets the device's packets in.
//! 3. The device connects with QUIC to the host's candidates, accepting only
//!    the certificate whose fingerprint arrived through the authenticated
//!    session ([`dial`]).
//! 4. Over the QUIC stream both sides run the same Noise_IKpsk2 handshake as
//!    over the relay — same paired-key and PSK checks — and only then switch.
//!
//! If anything fails (symmetric NATs, firewalls dropping UDP), the session
//! simply stays on the relay; the end-to-end encryption is identical either
//! way, so this is a change of path, never of protection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::frame::{Duplex, MAX_FRAME, is_gone, read_frame_io, write_frame};
use crate::wire::{STUN_LEN, STUN_PREFIX};
use crate::{hex, random};

const ALPN: &[u8] = b"bulge-direct/1";
const PUNCH: &[u8] = b"bulge-punch";

/// A UDP socket with the addresses peers may reach it at.
pub struct Prepared {
    socket: UdpSocket,
    pub candidates: Vec<SocketAddr>,
}

/// Bind a socket and learn its addresses: the local one (same LAN) and the
/// public one the relay sees (across NATs).
pub async fn prepare(relay: &str, step: Duration) -> Result<Prepared, String> {
    let relay_addr = tokio::net::lookup_host(relay).await.map_err(|e| format!("relay {relay}: {e}"))?.find(SocketAddr::is_ipv4).ok_or_else(|| format!("relay {relay} has no IPv4 address"))?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| format!("udp: {e}"))?;
    let port = socket.local_addr().map_err(|e| e.to_string())?.port();
    let mut candidates = Vec::new();
    // The interface address that routes toward the relay.
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).and_then(|p| p.connect(relay_addr).and(p.local_addr()));
    if let Ok(local) = probe {
        candidates.push(SocketAddr::new(local.ip(), port));
    }
    let token = random::<16>()?;
    let mut request = [STUN_PREFIX, &token].concat();
    request.resize(STUN_LEN, 0);
    let tokio_socket = tokio::net::UdpSocket::from_std({
        socket.set_nonblocking(true).map_err(|e| e.to_string())?;
        socket.try_clone().map_err(|e| e.to_string())?
    })
    .map_err(|e| e.to_string())?;
    let mut buf = [0u8; STUN_LEN];
    let public = timeout(step, async {
        for _ in 0..5 {
            tokio_socket.send_to(&request, relay_addr).await.map_err(|e| e.to_string())?;
            if let Ok(Ok((len, from))) = timeout(Duration::from_millis(500), tokio_socket.recv_from(&mut buf)).await
                && from == relay_addr
                && buf[..len].starts_with(STUN_PREFIX)
                && buf[..len].get(STUN_PREFIX.len()..).is_some_and(|rest| rest.starts_with(&token))
            {
                let text = std::str::from_utf8(&buf[STUN_PREFIX.len() + 16..len]).map_err(|e| e.to_string())?;
                return text.parse::<SocketAddr>().map_err(|e| e.to_string());
            }
        }
        Err("no STUN answer".to_string())
    })
    .await
    .map_err(|_| "no STUN answer".to_string())
    .and_then(|r| r);
    drop(tokio_socket);
    match public {
        Ok(addr) if !candidates.contains(&addr) => candidates.push(addr),
        Ok(_) => {}
        Err(error) if candidates.is_empty() => return Err(error),
        Err(_) => {}
    }
    Ok(Prepared { socket, candidates })
}

/// Parse candidates sent by the peer, keeping only sane unicast IPv4/IPv6
/// socket addresses (at most 8).
pub fn parse_candidates(list: &[String]) -> Vec<SocketAddr> {
    list.iter()
        .filter_map(|text| text.parse::<SocketAddr>().ok())
        .filter(|addr| addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast() && addr.ip() != IpAddr::V4(Ipv4Addr::BROADCAST))
        .take(8)
        .collect()
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(60)) {
        transport.max_idle_timeout(Some(idle));
    }
    Arc::new(transport)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Host side: a QUIC endpoint on the prepared socket with a fresh
/// certificate. Returns the certificate fingerprint (to send to the device
/// through the authenticated session) and a future yielding the device's
/// connection as a [`Duplex`].
pub fn listen(prepared: Prepared, device: Vec<SocketAddr>, wait: Duration) -> Result<(String, impl Future<Output = Result<Duplex, String>> + Send), String> {
    let certified = rcgen::generate_simple_self_signed(vec!["bulge-host".to_owned()]).map_err(|e| format!("certificate: {e}"))?;
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let fingerprint = hex(&Sha256::digest(&cert));
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|e| format!("tls: {e}"))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).map_err(|e| format!("quic: {e}"))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(transport());

    // Only the device's own addresses may connect (anyone else who finds
    // the port is refused before any TLS work).
    let allowed: Vec<IpAddr> = device.iter().map(SocketAddr::ip).collect();
    // Open our NAT toward the device before it connects.
    let puncher = prepared.socket.try_clone().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        for _ in 0..10 {
            for addr in &device {
                let _ = puncher.send_to(PUNCH, addr);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    });

    let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server), prepared.socket, Arc::new(quinn::TokioRuntime)).map_err(|e| format!("quic: {e}"))?;
    let accept = async move {
        let deadline = tokio::time::Instant::now() + wait;
        let incoming = loop {
            let incoming = tokio::time::timeout_at(deadline, endpoint.accept()).await.map_err(|_| "the device did not connect directly".to_string())?.ok_or("endpoint closed")?;
            let from = incoming.remote_address().ip();
            if allowed.iter().any(|ip| ip.to_canonical() == from.to_canonical()) {
                break incoming;
            }
            incoming.refuse();
        };
        let connection = timeout(wait, incoming).await.map_err(|_| "direct handshake timed out".to_string())?.map_err(|e| format!("quic: {e}"))?;
        let (send, recv) = timeout(wait, connection.accept_bi()).await.map_err(|_| "no stream".to_string())?.map_err(|e| format!("quic: {e}"))?;
        Ok(stream_duplex(endpoint, connection, send, recv))
    };
    Ok((fingerprint, accept))
}

/// Accepts exactly the certificate whose SHA-256 the host announced.
#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _name: &ServerName<'_>, _ocsp: &[u8], _now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if digest == self.fingerprint { Ok(ServerCertVerified::assertion()) } else { Err(rustls::Error::General("certificate is not the one announced by the host".into())) }
    }

    fn verify_tls12_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not used".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Device side: connect to the first host candidate that answers, pinning
/// the announced certificate.
pub async fn dial(prepared: Prepared, host: Vec<SocketAddr>, fingerprint: &str, wait: Duration) -> Result<Duplex, String> {
    let fingerprint = crate::unhex::<32>(fingerprint).map_err(|e| format!("fingerprint: {e}"))?;
    if host.is_empty() {
        return Err("the host offered no addresses".into());
    }
    let provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { fingerprint, provider }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).map_err(|e| format!("quic: {e}"))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport());
    let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, prepared.socket, Arc::new(quinn::TokioRuntime)).map_err(|e| format!("quic: {e}"))?;
    endpoint.set_default_client_config(client);

    // Try every candidate at once; the first to complete wins.
    let (tx, mut rx) = mpsc::channel(host.len());
    for addr in host {
        let (endpoint, tx) = (endpoint.clone(), tx.clone());
        tokio::spawn(async move {
            let result = match endpoint.connect(addr, "bulge-host") {
                Ok(connecting) => timeout(wait, connecting).await.map_err(|_| format!("{addr}: timed out")).and_then(|r| r.map_err(|e| format!("{addr}: {e}"))),
                Err(e) => Err(format!("{addr}: {e}")),
            };
            let _ = tx.send(result).await;
        });
    }
    drop(tx);
    let mut errors = Vec::new();
    while let Some(result) = rx.recv().await {
        match result {
            Ok(connection) => {
                let (send, recv) = connection.open_bi().await.map_err(|e| format!("quic: {e}"))?;
                return Ok(stream_duplex(endpoint, connection, send, recv));
            }
            Err(error) => errors.push(error),
        }
    }
    Err(format!("no direct path ({})", errors.join("; ")))
}

/// Frames over one QUIC stream. The endpoint and connection live as long as
/// the writer task.
fn stream_duplex(endpoint: quinn::Endpoint, connection: quinn::Connection, mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Duplex {
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);
    tokio::spawn(async move {
        let _keep = (&endpoint, &connection);
        while let Some(frame) = out_rx.recv().await {
            if write_frame(&mut send, &frame).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    });
    let (in_tx, in_rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let frame = match read_frame_io(&mut recv, MAX_FRAME).await {
                Ok(Some(frame)) => Ok(frame),
                // The peer finished the stream or the connection went away.
                Ok(None) => return,
                Err(error) if is_gone(&error) => return,
                Err(error) => Err(format!("read: {error}")),
            };
            let failed = frame.is_err();
            if in_tx.send(frame).await.is_err() || failed {
                return;
            }
        }
    });
    Duplex::new(out_tx, in_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_filtered() {
        let parsed = parse_candidates(&["1.2.3.4:5".into(), "0.0.0.0:5".into(), "1.2.3.4:0".into(), "x".into(), "224.0.0.1:9".into(), "[::1]:7".into()]);
        assert_eq!(parsed, vec!["1.2.3.4:5".parse::<SocketAddr>().unwrap(), "[::1]:7".parse().unwrap()]);
    }

    #[tokio::test]
    async fn quic_connects_with_the_pinned_certificate_and_refuses_others() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host_addr = socket.local_addr().unwrap();
        let host = Prepared { socket, candidates: vec![host_addr] };
        let device_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let device_addr = device_socket.local_addr().unwrap();
        let (fingerprint, accept) = listen(host, vec![device_addr], Duration::from_secs(5)).unwrap();
        let server = tokio::spawn(async move {
            let mut link = accept.await.unwrap();
            let got = link.recv().await.unwrap().unwrap();
            link.send([got.as_slice(), b"!"].concat()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let mut link = dial(Prepared { socket: device_socket, candidates: vec![] }, vec![host_addr], &fingerprint, Duration::from_secs(5)).await.unwrap();
        link.send(b"direct".to_vec()).await.unwrap();
        assert_eq!(link.recv().await.unwrap().unwrap(), b"direct!");
        server.await.unwrap();

        // A wrong fingerprint is refused.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host_addr = socket.local_addr().unwrap();
        let (_, accept) = listen(Prepared { socket, candidates: vec![] }, vec![], Duration::from_secs(2)).unwrap();
        tokio::spawn(accept);
        let device = Prepared { socket: UdpSocket::bind("127.0.0.1:0").unwrap(), candidates: vec![] };
        assert!(dial(device, vec![host_addr], &"00".repeat(32), Duration::from_secs(2)).await.is_err());
    }
}
