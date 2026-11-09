//! A TCP or TLS client stream with read timeouts, for protocols ureq does not
//! speak (WebSocket gateways, IRC, raw TCP). TLS uses rustls with the bundled
//! Mozilla roots, the same trust store ureq uses — or the `[network]` CA bundle, and
//! through the `[network]` HTTP proxy (`CONNECT`) unless NO_PROXY matches (`crate::http`).

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

pub enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

fn tls_slot() -> &'static RwLock<Option<Arc<rustls::ClientConfig>>> {
    static CFG: OnceLock<RwLock<Option<Arc<rustls::ClientConfig>>>> = OnceLock::new();
    CFG.get_or_init(Default::default)
}

/// Drop the cached TLS config (the CA bundle changed: `crate::http::configure`).
pub(crate) fn reset_tls() {
    *tls_slot().write().unwrap() = None;
}

/// The trust store for raw TLS streams: the `[network]` CA bundle when one is configured
/// (ent-037, the same roots every ureq agent uses), else the bundled Mozilla roots.
fn root_store() -> rustls::RootCertStore {
    if let Some(certs) = crate::http::custom_roots() {
        let mut roots = rustls::RootCertStore::empty();
        let (ok, _bad) = roots.add_parsable_certificates(certs.iter().map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec())));
        if ok > 0 {
            return roots;
        }
        eprintln!("seagent: warning: CA bundle has no usable certificates; using built-in roots");
    }
    rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let cached = !crate::http::overridden();
    if let Some(c) = tls_slot().read().unwrap().as_ref().filter(|_| cached) {
        return c.clone();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = Arc::new(rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("rustls protocol versions").with_root_certificates(root_store()).with_no_client_auth());
    if cached {
        *tls_slot().write().unwrap() = Some(cfg.clone());
    }
    cfg
}

/// Certificate pinning for LAN peers (SHA-256 of the leaf, the peer's identity): no CA and no
/// host-name check, but the handshake signature is still verified against the leaf's key.
/// `want == None` probes (accepts any certificate; read it with [`Stream::peer_fingerprint`]).
#[derive(Debug)]
struct Pin {
    want: Option<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Pin {
    fn verify_server_cert(&self, end_entity: &rustls::pki_types::CertificateDer<'_>, _i: &[rustls::pki_types::CertificateDer<'_>], _n: &rustls::pki_types::ServerName<'_>, _o: &[u8], _now: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = crate::crypto::hex(&crate::crypto::sha256(end_entity.as_ref()));
        match &self.want {
            Some(w) if !crate::crypto::ct_eq(w.as_bytes(), fp.as_bytes()) => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)),
            _ => Ok(rustls::client::danger::ServerCertVerified::assertion()),
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A client config that pins the server certificate's SHA-256 (`None`: probe).
pub(crate) fn pinned_config(want: Option<String>) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let want = want.map(|w| w.trim().to_ascii_lowercase().replace(':', ""));
    let pin = Arc::new(Pin { want, provider: provider.clone() });
    Arc::new(rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("rustls protocol versions").dangerous().with_custom_certificate_verifier(pin).with_no_client_auth())
}

/// RFC 6874: inside a URL's brackets a zone is written `%25<zone>`; turn it back into
/// `%<zone>` (a bare `%<zone>` is accepted as is).
pub fn decode_zone(bracketed: &str) -> String {
    match bracketed.split_once("%25") {
        Some((ip, zone)) if !zone.is_empty() && ip.parse::<std::net::Ipv6Addr>().is_ok() => format!("{ip}%{zone}"),
        _ => bracketed.to_string(),
    }
}

/// `host` without brackets or an IPv6 zone: what SNI and a `Host` header carry.
pub fn unzoned(host: &str) -> String {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h.contains(':') { h.split('%').next().unwrap_or(h).to_string() } else { h.to_string() }
}

/// `host:port` → a socket address. An IPv6 literal may carry a zone — `fe80::1%eth0` or
/// `fe80::1%12` (a Windows zone index; a URL's `%25` is decoded by [`Url::parse`]) — which
/// becomes the scope id, so a link-local LAN peer found by mDNS can be dialled.
pub fn resolve(host: &str, port: u16) -> io::Result<std::net::SocketAddr> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Some((ip, zone)) = h.split_once('%') {
        if let Ok(ip) = ip.parse::<std::net::Ipv6Addr>() {
            let scope = crate::mdns::iface::zone_index(zone).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no network interface `{zone}` for {h}")))?;
            return Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, scope)));
        }
    }
    (h, port).to_socket_addrs()?.next().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {h}")))
}

/// Open a TCP connection to `host:port`, through the configured HTTP proxy (`CONNECT`) unless
/// NO_PROXY says direct (ent-036: gateways and IRC follow the same proxy as HTTP).
fn open_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let target = format!("{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.to_string() });
    let c = crate::http::current();
    let proxy = crate::http::proxy_url(&c).filter(|_| !crate::http::is_direct(&format!("tcp://{target}/")));
    if crate::http::offline() && !crate::http::offline_allows(&c, host) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("offline mode: connection to {host} refused")));
    }
    let connect = |h: &str, p: u16| -> io::Result<TcpStream> {
        let addr = resolve(h, p)?;
        let tcp = TcpStream::connect_timeout(&addr, timeout)?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        Ok(tcp)
    };
    let Some(proxy) = proxy else { return connect(host, port) };
    let proxy = if proxy.contains("://") { proxy } else { format!("http://{proxy}") };
    let pu = Url::parse(&proxy).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("proxy {proxy}: {e}")))?;
    if !proxy.starts_with("http://") {
        // SOCKS / HTTPS proxies are ureq-only; a raw stream goes direct rather than failing.
        return connect(host, port);
    }
    let mut tcp = connect(&pu.host, pu.port)?;
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((_, rest)) = proxy.split_once("://") {
        if let Some((userinfo, _)) = rest.split('/').next().unwrap_or("").rsplit_once('@') {
            use base64::Engine;
            let up = urldecode(userinfo);
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(up)));
        }
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes())?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tcp.read(&mut b)? == 0 || head.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy closed during CONNECT"));
        }
        head.push(b[0]);
    }
    let status = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(io::Error::other(format!("proxy refused CONNECT {target}: {status}")));
    }
    Ok(tcp)
}

impl Stream {
    pub fn connect(host: &str, port: u16, tls: bool, timeout: Duration) -> io::Result<Stream> {
        let tcp = open_tcp(host, port, timeout)?;
        if !tls {
            return Ok(Stream::Plain(tcp));
        }
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| io::Error::other(e.to_string()))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        // Finish the handshake now so certificate errors surface at connect time.
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock)?;
        }
        Ok(Stream::Tls(Box::new(s)))
    }

    /// TLS to `host:port` trusting `ca_file` (PEM) instead of the process-wide roots — for a
    /// service with its own private CA (a SIEM's syslog-over-TLS listener). `None` = the
    /// usual roots ([`Stream::connect`]).
    pub fn connect_with_roots(host: &str, port: u16, ca_file: Option<&str>, timeout: Duration) -> io::Result<Stream> {
        let Some(ca) = ca_file.filter(|c| !c.trim().is_empty()) else { return Stream::connect(host, port, true, timeout) };
        let certs = crate::http::load_ca(ca).map_err(io::Error::other)?;
        let mut roots = rustls::RootCertStore::empty();
        let (ok, _) = roots.add_parsable_certificates(certs.iter().map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec())));
        if ok == 0 {
            return Err(io::Error::other(format!("{ca}: no usable certificates")));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = Arc::new(rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|e| io::Error::other(e.to_string()))?.with_root_certificates(roots).with_no_client_auth());
        let tcp = open_tcp(host, port, timeout)?;
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let conn = rustls::ClientConnection::new(cfg, name).map_err(|e| io::Error::other(e.to_string()))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock)?;
        }
        Ok(Stream::Tls(Box::new(s)))
    }

    /// TLS to a LAN peer pinned by certificate fingerprint (`None`: probe and report it via
    /// [`Stream::peer_fingerprint`]). Direct TCP: a LAN peer is never reached through the proxy.
    /// `host` may be an IPv6 literal with a zone (`fe80::1%eth0`, `fe80::1%12`, `%25`-encoded).
    pub fn connect_pinned(host: &str, port: u16, fingerprint: Option<&str>, timeout: Duration) -> io::Result<Stream> {
        let addr = resolve(host, port)?;
        let tcp = TcpStream::connect_timeout(&addr, timeout)?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        // The name only feeds SNI; an IP literal (without its zone) is fine.
        let name = rustls::pki_types::ServerName::try_from(unzoned(host)).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let conn = rustls::ClientConnection::new(pinned_config(fingerprint.map(str::to_string)), name).map_err(|e| io::Error::other(e.to_string()))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).map_err(|e| if fingerprint.is_some() && e.to_string().contains("ApplicationVerificationFailure") { io::Error::other("the peer's certificate fingerprint does not match the pinned one") } else { e })?;
        }
        Ok(Stream::Tls(Box::new(s)))
    }

    /// STARTTLS (SMTP 587, IMAP 143, IRC): upgrade a plain connection in place.
    pub fn starttls(self, host: &str) -> io::Result<Stream> {
        let Stream::Plain(tcp) = self else { return Ok(self) };
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| io::Error::other(e.to_string()))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock)?;
        }
        Ok(Stream::Tls(Box::new(s)))
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, Stream::Tls(_))
    }

    /// SHA-256 of the server's leaf certificate (lower-case hex), for pinning.
    pub fn peer_fingerprint(&self) -> Option<String> {
        match self {
            Stream::Plain(_) => None,
            Stream::Tls(s) => s.conn.peer_certificates().and_then(|c| c.first()).map(|c| crate::crypto::hex(&crate::crypto::sha256(c.as_ref()))),
        }
    }

    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(t) => t,
            Stream::Tls(s) => &s.sock,
        }
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.tcp().set_read_timeout(d)
    }

    pub fn shutdown(&self) {
        let _ = self.tcp().shutdown(std::net::Shutdown::Both);
    }

    /// End the session cleanly: TLS `close_notify` (so the peer sees a proper end of stream,
    /// not a truncation), then shut the socket.
    pub fn close(mut self) {
        if let Stream::Tls(s) = &mut self {
            s.conn.send_close_notify();
            let _ = s.conn.complete_io(&mut s.sock);
        }
        self.shutdown();
    }

    /// A handle that can unblock a reader from another thread.
    pub fn shutdown_handle(&self) -> io::Result<TcpStream> {
        self.tcp().try_clone()
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(t) => t.read(buf),
            Stream::Tls(s) => match s.read(buf) {
                // A peer that closes without close_notify is common (Discord, Slack); treat as EOF.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
                r => r,
            },
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(t) => t.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(t) => t.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// True for the error kinds a read timeout produces.
pub fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// One HTTP/1.1 request to a LAN peer over pinned TLS (`Connection: close`): `(status, body)`.
/// For node / cluster / pairing clients only — never a web or fetch tool (those keep the SSRF
/// rules of `seagent_security::url_safety`).
pub fn pinned_request(url: &str, fingerprint: &str, method: &str, headers: &[(&str, &str)], body: &[u8], timeout: Duration) -> Result<(u16, String), String> {
    let u = Url::parse(url)?;
    if !u.tls() {
        return Err(format!("{url}: a pinned request needs https://"));
    }
    let mut s = Stream::connect_pinned(&u.host, u.port, Some(fingerprint), timeout).map_err(|e| format!("{}:{}: {e}", u.host, u.port))?;
    let host = if u.host.contains(':') { format!("[{}]:{}", unzoned(&u.host), u.port) } else { format!("{}:{}", u.host, u.port) };
    let mut req = format!("{method} {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: seagent\r\nContent-Length: {}\r\nConnection: close\r\n", u.path, body.len());
    for (k, v) in headers {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            return Err("header contains a newline".into());
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).and_then(|_| s.write_all(body)).and_then(|_| s.flush()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let _ = (&mut s).take(8 << 20).read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).ok_or("malformed HTTP status")?;
    let mut rest = raw[split + 4..].to_vec();
    if head.lines().any(|l| l.to_ascii_lowercase().replace(' ', "") == "transfer-encoding:chunked") {
        let mut out = Vec::new();
        let mut cur = &rest[..];
        while let Some(i) = cur.windows(2).position(|w| w == b"\r\n") {
            let n = usize::from_str_radix(String::from_utf8_lossy(&cur[..i]).split(';').next().unwrap_or("").trim(), 16).map_err(|_| "bad chunk")?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(cur.get(i + 2..i + 2 + n).ok_or("short chunk")?);
            cur = cur.get(i + 4 + n..).unwrap_or(&[]);
        }
        rest = out;
    }
    Ok((status, String::from_utf8_lossy(&rest).into_owned()))
}

/// Parsed `scheme://host[:port]/path?query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path plus query, always starting with '/'.
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        let (scheme, rest) = s.split_once("://").ok_or_else(|| format!("not a URL: {s}"))?;
        let scheme = scheme.to_ascii_lowercase();
        let default = match scheme.as_str() {
            "http" | "ws" => 80,
            "https" | "wss" => 443,
            "irc" => 6667,
            "ircs" => 6697,
            other => return Err(format!("unsupported scheme {other}")),
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let path = if path.starts_with('?') { format!("/{path}") } else { path };
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(h) = authority.strip_prefix('[') {
            let (h, p) = h.split_once(']').ok_or("bad IPv6 host")?;
            (decode_zone(h), p.strip_prefix(':').map(|p| p.parse().map_err(|_| "bad port")).transpose()?.unwrap_or(default))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| format!("bad port in {s}"))?),
                None => (authority.to_string(), default),
            }
        };
        if host.is_empty() {
            return Err(format!("no host in {s}"));
        }
        Ok(Url { scheme, host, port, path })
    }

    pub fn tls(&self) -> bool {
        matches!(self.scheme.as_str(), "https" | "wss" | "ircs")
    }

    /// Host header value (port only when non-default).
    /// An IPv6 literal is bracketed and loses its zone (`[fe80::1]:8640`).
    pub fn host_header(&self) -> String {
        let default = if self.tls() { 443 } else { 80 };
        let host = if self.host.contains(':') { format!("[{}]", unzoned(&self.host)) } else { self.host.clone() };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Percent-encode for query strings and form bodies (RFC 3986 unreserved kept).
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `a=1&b=x%20y` → pairs.
pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (urldecode(k), urldecode(v)),
            None => (urldecode(p), String::new()),
        })
        .collect()
}

pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v))).collect::<Vec<_>>().join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_with_defaults_ports_and_queries() {
        let u = Url::parse("wss://gateway.discord.gg/?v=10&encoding=json").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str(), u.tls()), ("gateway.discord.gg", 443, "/?v=10&encoding=json", true));
        let u = Url::parse("ws://127.0.0.1:9000").unwrap();
        assert_eq!((u.port, u.path.as_str(), u.host_header()), (9000, "/", "127.0.0.1:9000".to_string()));
        let u = Url::parse("http://[::1]:8080/x?y").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("::1", 8080, "/x?y"));
        assert_eq!(Url::parse("https://h?q=1").unwrap().path, "/?q=1");
        assert_eq!(Url::parse("ircs://irc.libera.chat").unwrap().port, 6697);
        assert!(Url::parse("ftp://x").is_err() && Url::parse("nourl").is_err() && Url::parse("http://:80").is_err());
    }

    #[test]
    fn ipv6_zones_survive_urls_and_resolve_to_scope_ids() {
        // RFC 6874 URL form and the raw CLI form both reach the same host.
        let u = Url::parse("https://[fe80::1%2512]:8640/pair/client").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.host_header()), ("fe80::1%12", 8640, "[fe80::1]:8640".to_string()));
        assert_eq!(Url::parse("https://[fe80::1%12]:8640").unwrap().host, "fe80::1%12");
        assert_eq!(Url::parse("https://[fd00::2]").unwrap().host_header(), "[fd00::2]");
        assert_eq!(unzoned("[fe80::1%eth0]"), "fe80::1");
        assert_eq!(unzoned("studio.local"), "studio.local");
        let a = resolve("fe80::1%12", 8640).unwrap();
        assert_eq!(a, "[fe80::1%12]:8640".parse::<std::net::SocketAddr>().unwrap());
        assert!(resolve("fe80::1%no-such-interface-xyz", 8640).is_err());
        assert_eq!(resolve("[fd00::2]", 1).unwrap(), "[fd00::2]:1".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(resolve("192.168.1.20", 8640).unwrap(), "192.168.1.20:8640".parse::<std::net::SocketAddr>().unwrap());
    }

    #[test]
    fn percent_encoding_round_trips() {
        assert_eq!(urlencode("a b&c=中"), "a%20b%26c%3D%E4%B8%AD");
        assert_eq!(urldecode("a%20b+c%E4%B8%AD%zz%"), "a b c中%zz%");
        assert_eq!(parse_query("a=1&b=x%20y&flag"), vec![("a".into(), "1".into()), ("b".into(), "x y".into()), ("flag".into(), String::new())]);
        assert_eq!(form_encode(&[("k", "v w"), ("x", "&")]), "k=v%20w&x=%26");
    }

    #[test]
    fn raw_streams_tunnel_through_the_configured_proxy() {
        use std::net::TcpListener;
        // Fake proxy: answers CONNECT, then echoes one line back through the tunnel.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
            String::from_utf8_lossy(&head).to_string()
        });
        let c = crate::http::NetConfig { proxy: Some(format!("http://user:pw@127.0.0.1:{port}")), ..Default::default() };
        crate::http::with_config(c, || {
            let mut s = Stream::connect("10.255.255.2", 6667, false, Duration::from_secs(5)).unwrap();
            s.write_all(b"PING\n").unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"PING\n");
        });
        let head = h.join().unwrap();
        assert!(head.starts_with("CONNECT 10.255.255.2:6667 HTTP/1.1"), "{head}");
        assert!(head.contains("Proxy-Authorization: Basic dXNlcjpwdw=="), "{head}");
    }
}
