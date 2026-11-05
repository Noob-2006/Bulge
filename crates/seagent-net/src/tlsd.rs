//! Native TLS and mutual TLS for [`crate::httpd`] servers (ent-121), and X.509 identities
//! (SPIFFE IDs, ent-059).
//!
//! [`crate::httpd::Server::bind_tls`] puts a TLS terminator in front of an ordinary plain
//! server bound to an ephemeral loopback port. Every request is one connection (the plain
//! server never keeps a connection alive), so the terminator reads the decrypted request head,
//! drops any `x-seagent-tls-*` header the client sent, adds
//!
//! * `x-seagent-tls-secret` — a per-process random value: the wrapped handler refuses a request
//!   without it, so a local process that finds the loopback port cannot forge the others;
//! * `x-seagent-tls-peer` — the real TCP peer (the plain server only sees the terminator);
//! * `x-seagent-tls-client` — the verified client certificate's identity (see [`CertIdentity`]),
//!   only when the client presented one that chains to `client_ca`,
//!
//! and then pumps bytes both ways, so SSE and WebSocket upgrades work unchanged. The handler
//! sees `Request::peer` = the real peer and, for mTLS, `x-seagent-tls-client` — the one header an
//! application may trust, because the wrapper strips every client-sent copy.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Whether (and how) clients must present a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuth {
    /// No client certificates requested.
    #[default]
    Off,
    /// Requested and verified when sent; a client without one still connects (token auth).
    Optional,
    /// Required: the handshake fails without a certificate that chains to `client_ca`.
    Require,
}

impl ClientAuth {
    pub fn parse(s: &str) -> Result<ClientAuth, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "none" | "false" => Ok(ClientAuth::Off),
            "optional" | "request" => Ok(ClientAuth::Optional),
            "require" | "required" | "true" => Ok(ClientAuth::Require),
            o => Err(format!("client_auth `{o}`: expected off, optional or require")),
        }
    }
}

/// PEM paths for a TLS listener.
#[derive(Debug, Clone, Default)]
pub struct ServerTls {
    pub cert: String,
    pub key: String,
    /// Roots that client certificates must chain to (mTLS). Required unless `client_auth` is off.
    pub client_ca: Option<String>,
    pub client_auth: ClientAuth,
}

fn key_der(k: &ureq::tls::PrivateKey<'static>) -> rustls::pki_types::PrivateKeyDer<'static> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    // pki-types recognises PKCS#1 / SEC1 / PKCS#8 from the DER structure itself.
    PrivateKeyDer::try_from(k.der().to_vec()).unwrap_or_else(|_| PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.der().to_vec())))
}

fn certs_der(v: &[ureq::tls::Certificate<'static>]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    v.iter().map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec())).collect()
}

impl ServerTls {
    /// Validate and build the rustls server config (clear errors for `seagent doctor` / start-up).
    pub fn config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        if self.cert.trim().is_empty() || self.key.trim().is_empty() {
            return Err("TLS needs both a certificate (cert) and a private key (key)".into());
        }
        let (chain, key) = crate::http::load_cert_and_key(&self.cert, &self.key)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let b = rustls::ServerConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?;
        let b = match (self.client_auth, &self.client_ca) {
            (ClientAuth::Off, _) => b.with_no_client_auth(),
            (_, None) => return Err("client_auth needs client_ca (the PEM roots client certificates must chain to)".into()),
            (mode, Some(ca)) => {
                let mut roots = rustls::RootCertStore::empty();
                let certs = crate::http::load_ca(ca)?;
                let (ok, _) = roots.add_parsable_certificates(certs_der(&certs));
                if ok == 0 {
                    return Err(format!("client_ca {ca}: no usable certificates"));
                }
                let v = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
                let v = if mode == ClientAuth::Optional { v.allow_unauthenticated() } else { v };
                b.with_client_cert_verifier(v.build().map_err(|e| format!("client_ca {ca}: {e}"))?)
            }
        };
        let cfg = b.with_single_cert(certs_der(&chain), key_der(&key)).map_err(|e| format!("certificate {}: {e}", self.cert))?;
        Ok(Arc::new(cfg))
    }
}

/// Identity material of an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertIdentity {
    /// `subjectAltName` URIs (a SPIFFE X.509-SVID carries exactly one `spiffe://` URI).
    pub uris: Vec<String>,
    pub dns: Vec<String>,
    /// SHA-256 of the DER certificate, lower-case hex.
    pub fingerprint: String,
}

impl CertIdentity {
    pub fn from_der(der: &[u8]) -> CertIdentity {
        let (uris, dns) = san(der);
        CertIdentity { uris, dns, fingerprint: crate::crypto::hex(&crate::crypto::sha256(der)) }
    }
    /// The SPIFFE ID, if the certificate is an SVID.
    pub fn spiffe_id(&self) -> Option<&str> {
        self.uris.iter().find(|u| u.starts_with("spiffe://")).map(String::as_str)
    }
    /// One stable name: the SPIFFE ID, else the first URI, else `dns:<name>`, else
    /// `sha256:<fingerprint>`.
    pub fn primary(&self) -> String {
        self.spiffe_id().map(str::to_string).or_else(|| self.uris.first().cloned()).or_else(|| self.dns.first().map(|d| format!("dns:{d}"))).unwrap_or_else(|| format!("sha256:{}", self.fingerprint))
    }
}

/// One DER TLV at `i`: `(tag, content start, content end)`.
fn tlv(b: &[u8], i: usize) -> Option<(u8, usize, usize)> {
    let tag = *b.get(i)?;
    let l0 = *b.get(i + 1)? as usize;
    let (len, start) = if l0 < 0x80 {
        (l0, i + 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | *b.get(i + 2 + k)? as usize;
        }
        (len, i + 2 + n)
    };
    let end = start.checked_add(len)?;
    (end <= b.len()).then_some((tag, start, end))
}

/// `subjectAltName` (2.5.29.17) URIs and DNS names. A small DER walk: the extension's OID,
/// an optional `critical` BOOLEAN, then an OCTET STRING holding `SEQUENCE OF GeneralName`.
fn san(der: &[u8]) -> (Vec<String>, Vec<String>) {
    const OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
    let (mut uris, mut dns) = (vec![], vec![]);
    let Some(pos) = der.windows(OID.len()).position(|w| w == OID) else { return (uris, dns) };
    let mut i = pos + OID.len();
    let Some((mut tag, mut s, mut e)) = tlv(der, i) else { return (uris, dns) };
    if tag == 0x01 {
        i = e;
        match tlv(der, i) {
            Some(t) => (tag, s, e) = t,
            None => return (uris, dns),
        }
    }
    if tag != 0x04 {
        return (uris, dns);
    }
    let Some((0x30, mut j, end)) = tlv(der, s).filter(|t| t.2 <= e) else { return (uris, dns) };
    while j < end {
        let Some((t, cs, ce)) = tlv(der, j) else { break };
        let text = String::from_utf8_lossy(&der[cs..ce]).into_owned();
        match t {
            0x86 => uris.push(text),
            0x82 => dns.push(text.to_ascii_lowercase()),
            _ => {}
        }
        j = ce;
    }
    (uris, dns)
}

/// Read every certificate of a PEM file and return the first one's identity.
pub fn identity_of_pem(path: &str) -> Result<CertIdentity, String> {
    let certs = crate::http::load_ca(path).map_err(|e| e.replace("CA bundle", "certificate"))?;
    Ok(CertIdentity::from_der(certs[0].der()))
}

/// Header names the terminator owns.
pub const H_SECRET: &str = "x-seagent-tls-secret";
pub const H_PEER: &str = "x-seagent-tls-peer";
pub const H_CLIENT: &str = "x-seagent-tls-client";

/// Serve one TLS connection: handshake, forward the (rewritten) request to the plain server at
/// `inner`, then pump bytes both ways until either side closes.
pub(crate) fn terminate(tcp: TcpStream, cfg: Arc<rustls::ServerConfig>, inner: SocketAddr, secret: &str, timeout: Duration) -> io::Result<()> {
    let peer = tcp.peer_addr()?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let conn = rustls::ServerConnection::new(cfg).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let client = tls.conn.peer_certificates().and_then(|c| c.first()).map(|c| CertIdentity::from_der(c.as_ref()).primary());
    let (head, rest) = crate::ws::read_head(&mut tls, 32 * 1024)?;
    let mut lines = head.trim_end_matches("\r\n").split("\r\n");
    let mut out = format!("{}\r\n", lines.next().unwrap_or(""));
    for l in lines {
        let name = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if !name.starts_with("x-seagent-tls-") {
            out.push_str(l);
            out.push_str("\r\n");
        }
    }
    out.push_str(&format!("{H_SECRET}: {secret}\r\n{H_PEER}: {peer}\r\n"));
    if let Some(c) = client.filter(|c| !c.contains(['\r', '\n'])) {
        out.push_str(&format!("{H_CLIENT}: {c}\r\n"));
    }
    out.push_str("\r\n");
    let mut up = TcpStream::connect_timeout(&inner, timeout)?;
    up.write_all(out.as_bytes())?;
    up.write_all(&rest)?;
    pump(tls, up)
}

fn would_block(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

fn pump(mut tls: rustls::StreamOwned<rustls::ServerConnection, TcpStream>, mut up: TcpStream) -> io::Result<()> {
    const TICK: Duration = Duration::from_millis(20);
    tls.sock.set_read_timeout(Some(TICK))?;
    up.set_read_timeout(Some(TICK))?;
    let mut buf = vec![0u8; 16 * 1024];
    let (mut client_open, mut idle) = (true, Duration::ZERO);
    loop {
        let mut moved = false;
        if client_open {
            match tls.read(&mut buf) {
                Ok(0) => {
                    client_open = false;
                    let _ = up.shutdown(std::net::Shutdown::Write);
                }
                Ok(n) => {
                    up.write_all(&buf[..n])?;
                    moved = true;
                }
                Err(e) if would_block(&e) => {}
                Err(_) => {
                    client_open = false;
                    let _ = up.shutdown(std::net::Shutdown::Write);
                }
            }
        }
        match up.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                tls.write_all(&buf[..n])?;
                tls.flush()?;
                moved = true;
            }
            Err(e) if would_block(&e) => {}
            Err(_) => break,
        }
        idle = if moved { Duration::ZERO } else { idle + TICK };
        // The plain server bounds every request itself; this only reaps a wedged pair.
        if !client_open && idle > Duration::from_secs(30) {
            break;
        }
    }
    tls.conn.send_close_notify();
    let _ = tls.conn.complete_io(&mut tls.sock);
    let _ = tls.sock.shutdown(std::net::Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn td(f: &str) -> String {
        format!("{}/src/testdata/{f}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn spiffe_ids_and_dns_names_come_out_of_the_san() {
        let c = identity_of_pem(&td("client.pem")).unwrap();
        assert_eq!(c.spiffe_id(), Some("spiffe://example.org/ark/node/n1"));
        assert_eq!(c.primary(), "spiffe://example.org/ark/node/n1");
        let s = identity_of_pem(&td("server.pem")).unwrap();
        assert_eq!(s.dns, vec!["localhost".to_string()]);
        assert_eq!(s.primary(), "dns:localhost");
        assert_eq!(s.fingerprint.len(), 64);
        assert_eq!(CertIdentity::from_der(b"not der").primary().len(), "sha256:".len() + 64);
    }

    #[test]
    fn config_errors_are_clear() {
        assert!(ServerTls::default().config().unwrap_err().contains("certificate"));
        let t = ServerTls { cert: td("server.pem"), key: td("server.key"), client_ca: None, client_auth: ClientAuth::Require };
        assert!(t.config().unwrap_err().contains("client_ca"));
        assert!(ServerTls { client_auth: ClientAuth::Off, ..t.clone() }.config().is_ok());
        assert!(ServerTls { client_ca: Some(td("ca.pem")), ..t }.config().is_ok());
        assert_eq!(ClientAuth::parse("required").unwrap(), ClientAuth::Require);
        assert!(ClientAuth::parse("maybe").is_err());
    }
}
