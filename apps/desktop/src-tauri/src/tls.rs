//! TLS to a paired host with **certificate pinning** (SHA-256 of the leaf certificate, the
//! host's identity — no CA, no host name check), plus a loopback tunnel so the WebView can load
//! the host's console as `http://127.0.0.1:<port>` while every byte on the LAN is TLS to the
//! pinned host. This avoids teaching WKWebView / Android WebView about self-signed certificates.
//! No Tauri types here (unit-testable).

use crate::pair::Address;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub fn fingerprint(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug)]
struct Pin {
    /// `None`: probe (accept anything, record what was seen).
    want: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _name: &ServerName<'_>, _ocsp: &[u8], _now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap() = Some(fp.clone());
        match &self.want {
            None => Ok(ServerCertVerified::assertion()),
            Some(w) if ct_eq(w, &fp) => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)),
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn config(want: Option<String>, seen: Arc<Mutex<Option<String>>>) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let pin = Pin { want, seen, provider: provider.clone() };
    let cfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|e| e.to_string())?.dangerous().with_custom_certificate_verifier(Arc::new(pin)).with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    // The name is only used for SNI here: identity is the pin.
    ServerName::try_from(host.to_string()).map_err(|_| format!("bad host name `{host}`"))
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);

async fn connect(addr: &Address, want: Option<String>) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, String), String> {
    let seen = Arc::new(Mutex::new(None));
    let cfg = config(want.clone(), seen.clone())?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((addr.host.as_str(), addr.port))).await.map_err(|_| format!("{}: connection timed out", addr.authority()))?.map_err(|e| format!("{}: {e}", addr.authority()))?;
    let _ = tcp.set_nodelay(true);
    let tls = tokio::time::timeout(CONNECT_TIMEOUT, tokio_rustls::TlsConnector::from(cfg).connect(server_name(&addr.host)?, tcp)).await.map_err(|_| "TLS handshake timed out".to_string())?;
    let fp = seen.lock().unwrap().clone().unwrap_or_default();
    match tls {
        Ok(s) => Ok((s, fp)),
        Err(_) if want.is_some() && !fp.is_empty() => Err(format!("the host's certificate changed (fingerprint {}); if you reinstalled it, forget and pair it again", crate::pair::short_fingerprint(&fp))),
        Err(e) => Err(format!("TLS: {e}")),
    }
}

/// Connect once without a pin and report the certificate fingerprint (trust on first use: the
/// UI shows it next to the one the host prints so the user can compare).
pub async fn probe(addr: &Address) -> Result<String, String> {
    let (mut s, fp) = connect(addr, None).await?;
    let _ = s.shutdown().await;
    if fp.is_empty() {
        return Err("the host presented no certificate".into());
    }
    Ok(fp)
}

/// `POST <path>` with a JSON body over pinned TLS (HTTP/1.1, `Connection: close`).
pub async fn post_json(addr: &Address, pin: &str, path: &str, body: &Value) -> Result<(u16, Value), String> {
    let (mut s, _) = connect(addr, Some(pin.to_string())).await?;
    let b = body.to_string();
    let req = format!("POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", addr.authority(), b.len());
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), (&mut s).take(4 << 20).read_to_end(&mut raw)).await.map_err(|_| "the host did not answer".to_string())?;
    parse_response(&raw)
}

/// Status + JSON body of an HTTP/1.1 response (content-length, chunked, or until close).
pub fn parse_response(raw: &[u8]) -> Result<(u16, Value), String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).ok_or("malformed HTTP status")?;
    let mut body = raw[split + 4..].to_vec();
    if head.lines().any(|l| l.to_ascii_lowercase().replace(' ', "") == "transfer-encoding:chunked") {
        let mut out = Vec::new();
        let mut rest = &body[..];
        while let Some(i) = rest.windows(2).position(|w| w == b"\r\n") {
            let n = usize::from_str_radix(String::from_utf8_lossy(&rest[..i]).split(';').next().unwrap_or("").trim(), 16).map_err(|_| "bad chunk")?;
            if n == 0 {
                break;
            }
            let start = i + 2;
            out.extend_from_slice(rest.get(start..start + n).ok_or("short chunk")?);
            rest = rest.get(start + n + 2..).unwrap_or(&[]);
        }
        body = out;
    }
    let v = if body.iter().all(|b| b.is_ascii_whitespace()) { Value::Null } else { serde_json::from_slice(&body).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).chars().take(300).collect())) };
    Ok((status, v))
}

/// A loopback listener that forwards every connection over pinned TLS to the host.
pub struct Tunnel {
    pub port: u16,
    pub host_id: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Tunnel {
    /// Bind `127.0.0.1:<preferred>` (or any free port) and forward to `addr` pinned to `pin`.
    /// The first upstream connection is made before returning, so a wrong pin fails here.
    pub async fn start(host_id: &str, addr: Address, pin: String, preferred: u16) -> Result<Tunnel, String> {
        let (mut first, _) = connect(&addr, Some(pin.clone())).await?;
        let _ = first.shutdown().await;
        let listener = match TcpListener::bind(("127.0.0.1", preferred)).await {
            Ok(l) if preferred != 0 => l,
            _ => TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| e.to_string())?,
        };
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let task = tokio::spawn(async move {
            while let Ok((mut local, _)) = listener.accept().await {
                let (addr, pin) = (addr.clone(), pin.clone());
                tokio::spawn(async move {
                    let _ = local.set_nodelay(true);
                    match connect(&addr, Some(pin)).await {
                        Ok((mut up, _)) => {
                            let _ = tokio::io::copy_bidirectional(&mut local, &mut up).await;
                        }
                        Err(e) => {
                            let msg = format!("SE Agent could not reach the host: {e}");
                            let _ = local.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len()).as_bytes()).await;
                        }
                    }
                });
            }
        });
        Ok(Tunnel { port, host_id: host_id.to_string(), task })
    }
}
