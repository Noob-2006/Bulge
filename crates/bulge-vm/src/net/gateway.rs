//! Two-key egress gateway (host side).
//!
//! The guest has no ordinary network interface. Its only way out is this gateway,
//! reached over a dedicated vsock port that libkrun bridges to a host-private unix
//! socket in the per-VM runtime directory. To open ANY outbound connection the
//! guest must present two secrets on the wire:
//!
//!   1. the gateway token — the host's consent that this VM may egress at all;
//!   2. the per-VM key — proof the request comes from this exact sandbox.
//!
//! Both are minted per launch, delivered once through the sealed bootstrap (only
//! sandboxd ever holds them), and checked here in constant time. Even with both
//! keys the target host must match the allowlist, and every resolved IP is passed
//! through the same special-use/host filter as the packet path, so an allowlisted
//! name that resolves to a private or metadata address is still refused (DNS
//! rebinding defence). The upshot: content the agent pulls into the VM — a web
//! page, a downloaded script — has no interface and no keys, so it cannot phone
//! home; the agent's own fetches can only reach approved hosts.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use crate::net::policy::is_forbidden_destination;

/// Vsock port the guest dials for the egress gateway (host listens on the bridged
/// unix socket). Distinct from the control port (1024). Shared with the guest via
/// `bulge_proto`.
pub use bulge_proto::msg::GATEWAY_VSOCK_PORT;

/// Largest request header we will read before the target (keys + host:port).
const MAX_HEADER: usize = 1024;

#[derive(Debug, Default)]
pub struct GatewayStats {
    pub allowed: AtomicU64,
    pub denied_auth: AtomicU64,
    pub denied_policy: AtomicU64,
    pub connect_failed: AtomicU64,
}

/// What the guest requested: open a tunnel to `host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub token: String,
    pub key: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Malformed,
    BadPort,
}

/// Parse one request line: `<token> <key> <host> <port>` (single spaces). The
/// host must be a bare name or IP literal — no scheme, path, or embedded spaces.
pub fn parse_request(line: &str) -> Result<Request, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.split(' ');
    let (Some(token), Some(key), Some(host), Some(port), None) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ParseError::Malformed);
    };
    if token.is_empty() || key.is_empty() || host.is_empty() || host.contains('/') {
        return Err(ParseError::Malformed);
    }
    let port: u16 = port.parse().map_err(|_| ParseError::BadPort)?;
    if port == 0 {
        return Err(ParseError::BadPort);
    }
    Ok(Request { token: token.to_owned(), key: key.to_owned(), host: host.to_owned(), port })
}

/// Constant-time byte comparison (no early exit on first mismatch).
fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Both keys must match the session's secrets.
pub fn authorized(request: &Request, token: &str, key: &str) -> bool {
    secret_eq(&request.token, token) && secret_eq(&request.key, key)
}

/// A host is allowed when it matches an allowlist suffix on a label boundary
/// (`github.com` matches `github.com` and `api.github.com`, not `evilgithub.com`
/// nor `github.com.attacker.net`). An empty allowlist allows nothing.
pub fn host_allowed(host: &str, allow_suffixes: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // A bare IP literal is never "allowlisted by name"; it must be an explicit
    // entry. (Resolved IPs are filtered separately for special-use ranges.)
    allow_suffixes.iter().any(|suffix| {
        let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
    })
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub token: String,
    pub key: String,
    pub allow_suffixes: Vec<String>,
    pub stats: Arc<GatewayStats>,
}

/// Serve the gateway on `socket_path` (the host end of the bridged vsock port)
/// until the listener is dropped. Each guest connection is authenticated,
/// policy-checked, and — if approved — spliced to the real destination.
pub fn serve(listener: UnixListener, config: GatewayConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                let _ = handle(stream, config).await;
            });
        }
    })
}

/// Bind the host end of the gateway's vsock bridge.
pub fn bind(socket_path: &Path) -> std::io::Result<UnixListener> {
    // A stale socket from a crashed run would block the bind.
    let _ = std::fs::remove_file(socket_path);
    UnixListener::bind(socket_path)
}

async fn handle(mut stream: UnixStream, config: GatewayConfig) -> std::io::Result<()> {
    let line = match read_header_line(&mut stream).await {
        Some(line) => line,
        None => return Ok(()),
    };
    let request = match parse_request(&line) {
        Ok(request) => request,
        Err(_) => return deny(&mut stream, &config.stats.denied_policy, "ERR malformed").await,
    };
    if !authorized(&request, &config.token, &config.key) {
        return deny(&mut stream, &config.stats.denied_auth, "ERR unauthorized").await;
    }
    if !host_allowed(&request.host, &config.allow_suffixes) {
        return deny(&mut stream, &config.stats.denied_policy, "ERR host not allowed").await;
    }
    // Resolve and reject any address in a forbidden (private/metadata/…) range.
    let targets = resolve_allowed(&request.host, request.port);
    if targets.is_empty() {
        return deny(&mut stream, &config.stats.denied_policy, "ERR unresolved or forbidden").await;
    }
    // Try each allowed address in turn (so a host with an unreachable IPv6 still
    // connects over IPv4).
    let mut upstream = None;
    for target in targets {
        if let Ok(stream) = TcpStream::connect(target).await {
            upstream = Some(stream);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        return deny(&mut stream, &config.stats.connect_failed, "ERR connect failed").await;
    };
    config.stats.allowed.fetch_add(1, Ordering::Relaxed);
    stream.write_all(b"OK\n").await?;
    // Tunnel bytes until either side closes.
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    Ok(())
}

async fn deny(stream: &mut UnixStream, counter: &AtomicU64, message: &str) -> std::io::Result<()> {
    counter.fetch_add(1, Ordering::Relaxed);
    let _ = stream.write_all(format!("{message}\n").as_bytes()).await;
    Ok(())
}

/// Read a single `\n`-terminated header line, bounded by `MAX_HEADER`.
async fn read_header_line(stream: &mut UnixStream) -> Option<String> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() > MAX_HEADER {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    String::from_utf8(buf).ok()
}

/// Resolve `host:port`, returning every address that is NOT in a forbidden
/// range. Empty if resolution fails or every address is forbidden.
fn resolve_allowed(host: &str, port: u16) -> Vec<SocketAddr> {
    match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs.filter(|addr| !is_forbidden_destination(addr.ip())).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_good_and_bad_requests() {
        let r = parse_request("tok key example.com 443\n").unwrap();
        assert_eq!(r, Request { token: "tok".into(), key: "key".into(), host: "example.com".into(), port: 443 });
        assert_eq!(parse_request("tok key example.com"), Err(ParseError::Malformed));
        assert_eq!(parse_request("tok key example.com 443 extra"), Err(ParseError::Malformed));
        assert_eq!(parse_request("tok key http://example.com/x 443"), Err(ParseError::Malformed));
        assert_eq!(parse_request("tok key example.com 0"), Err(ParseError::BadPort));
        assert_eq!(parse_request("tok key example.com nope"), Err(ParseError::BadPort));
    }

    #[test]
    fn auth_requires_both_keys_and_is_length_safe() {
        let r = Request { token: "aaa".into(), key: "bbb".into(), host: "h".into(), port: 1 };
        assert!(authorized(&r, "aaa", "bbb"));
        assert!(!authorized(&r, "aaa", "zzz"));
        assert!(!authorized(&r, "zzz", "bbb"));
        assert!(!authorized(&r, "aa", "bbb")); // length mismatch
    }

    #[test]
    fn allowlist_is_label_bounded() {
        let allow = vec!["github.com".to_string(), "crates.io".to_string()];
        assert!(host_allowed("github.com", &allow));
        assert!(host_allowed("api.github.com", &allow));
        assert!(host_allowed("static.crates.io", &allow));
        assert!(!host_allowed("evilgithub.com", &allow));
        assert!(!host_allowed("github.com.attacker.net", &allow));
        assert!(!host_allowed("example.com", &allow));
        assert!(!host_allowed("anything", &[]), "empty allowlist allows nothing");
    }

    #[test]
    fn resolve_rejects_forbidden_addresses() {
        // localhost resolves only to loopback, which is forbidden.
        assert!(resolve_allowed("localhost", 80).is_empty());
    }
}
