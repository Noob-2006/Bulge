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

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::Mutex;

use bulge_guard::RealWorldPolicy;

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
    /// Real-world hosts refused because there was no human to ask (or the human
    /// declined). Kept separate so the UI can show the boundary doing its job.
    pub denied_real_world: AtomicU64,
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
/// nor `github.com.attacker.net`). The single entry `"*"` means "any public host"
/// (the roadmap's allow-public mode); resolved IPs are still filtered for
/// private/LAN/metadata ranges separately. An empty allowlist allows nothing.
pub fn host_allowed(host: &str, allow_suffixes: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // A bare IP literal is never "allowlisted by name"; it must be an explicit
    // entry. (Resolved IPs are filtered separately for special-use ranges.)
    allow_suffixes.iter().any(|suffix| {
        let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        suffix == "*" || (!suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}"))))
    })
}

/// A request for the user to approve egress to a host the auto-allowlist does not
/// cover (collaborative mode). The gateway blocks the connection until `reply` is
/// answered: `true` opens it (and the host is remembered for the rest of the
/// session), `false` refuses it. This is the hook behind the roadmap's "only ask
/// when data egresses a non-model API": package/dev sources are auto-allowed, the
/// model API never comes through here (it is a host-side call), so what remains is
/// the agent reaching an arbitrary third-party host from inside the VM.
#[derive(Debug)]
pub struct EgressApproval {
    pub host: String,
    pub port: u16,
    pub reply: tokio::sync::oneshot::Sender<bool>,
}

/// Channel the gateway asks egress approval on. The app owns the receiver,
/// surfaces each prompt, and answers its `reply`.
pub type EgressApprovalTx = tokio::sync::mpsc::UnboundedSender<EgressApproval>;

#[derive(Clone)]
pub struct GatewayConfig {
    pub token: String,
    pub key: String,
    pub allow_suffixes: Vec<String>,
    pub stats: Arc<GatewayStats>,
    /// When set, a host not covered by `allow_suffixes` raises an approval request
    /// here instead of an outright deny. `None` keeps the plain allow/deny gateway.
    pub approvals: Option<EgressApprovalTx>,
    /// Hosts the user has already approved this session (so repeats don't re-ask).
    pub approved: Arc<Mutex<HashSet<String>>>,
    /// The host's own interface addresses. A destination that resolves to one of
    /// these is refused even when it is a public IP, so an allowlisted/approved
    /// name can't be pointed back at a service on this machine.
    pub host_addrs: Arc<HashSet<IpAddr>>,
    /// Payment/checkout/wallet hosts. Even an allow-public `"*"` cannot reach
    /// these without a human: without an approval channel they are denied.
    pub real_world: Arc<RealWorldPolicy>,
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
    if config.real_world.host_is_real_world(&request.host) {
        // Real-world hosts (payments, checkout, wallets) are a separate boundary
        // that sits BEFORE the allowlist: allow-public `"*"` does not reach them.
        // With a human channel ask every time (never remember approval); without
        // one, fail closed.
        let Some(tx) = &config.approvals else {
            return deny(&mut stream, &config.stats.denied_real_world, "ERR real-world host requires a human").await;
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if tx.send(EgressApproval { host: request.host.clone(), port: request.port, reply: reply_tx }).is_err() {
            return deny(&mut stream, &config.stats.denied_real_world, "ERR egress approval unavailable").await;
        }
        // Block this connection until the user decides (or the prompt is dropped).
        // Deliberately NOT added to `approved`: every real-world connection asks.
        if !reply_rx.await.unwrap_or(false) {
            return deny(&mut stream, &config.stats.denied_real_world, "ERR egress denied by user").await;
        }
    } else if !host_allowed(&request.host, &config.allow_suffixes) {
        // Not on the auto-allow list. Without an approval channel this is a plain
        // deny; with one, ask the user (once per host per session).
        let Some(tx) = &config.approvals else {
            return deny(&mut stream, &config.stats.denied_policy, "ERR host not allowed").await;
        };
        let host_key = request.host.trim_end_matches('.').to_ascii_lowercase();
        if !config.approved.lock().await.contains(&host_key) {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if tx.send(EgressApproval { host: request.host.clone(), port: request.port, reply: reply_tx }).is_err() {
                return deny(&mut stream, &config.stats.denied_policy, "ERR egress approval unavailable").await;
            }
            // Block this connection until the user decides (or the prompt is dropped).
            if !reply_rx.await.unwrap_or(false) {
                return deny(&mut stream, &config.stats.denied_policy, "ERR egress denied by user").await;
            }
            config.approved.lock().await.insert(host_key);
        }
    }
    // Resolve and reject any address in a forbidden (private/metadata/…) range
    // or belonging to this host itself.
    let targets = resolve_allowed(&request.host, request.port, &config.host_addrs);
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

/// Whether an address must never be connected to: a special-use/private/metadata
/// range, or one of the host's own interface addresses (including its public IP).
fn addr_forbidden(ip: IpAddr, host_addrs: &HashSet<IpAddr>) -> bool {
    is_forbidden_destination(ip) || host_addrs.contains(&ip)
}

/// Resolve `host:port`, returning every address that is NOT forbidden. Empty if
/// resolution fails or every address is forbidden.
fn resolve_allowed(host: &str, port: u16, host_addrs: &HashSet<IpAddr>) -> Vec<SocketAddr> {
    match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs.filter(|addr| !addr_forbidden(addr.ip(), host_addrs)).collect(),
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
        let any = vec!["*".to_string()];
        assert!(host_allowed("example.com", &any), "'*' allows any public host");
        assert!(host_allowed("deep.sub.example.org", &any));
    }

    #[test]
    fn resolve_rejects_forbidden_addresses() {
        // localhost resolves only to loopback, which is forbidden.
        assert!(resolve_allowed("localhost", 80, &HashSet::new()).is_empty());
    }

    #[test]
    fn addr_forbidden_covers_special_ranges_and_host_own_ip() {
        use std::net::Ipv4Addr;
        // A public IP is normally fine...
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(!addr_forbidden(public, &HashSet::new()));
        // ...but not if it is one of this host's own addresses.
        let host_addrs: HashSet<IpAddr> = [public].into_iter().collect();
        assert!(addr_forbidden(public, &host_addrs), "host's own public IP must be refused");
        // Special-use ranges are always forbidden regardless of host set.
        assert!(addr_forbidden(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), &HashSet::new()));
    }

    fn gw(approvals: Option<EgressApprovalTx>) -> GatewayConfig {
        gw_with(approvals, RealWorldPolicy::defaults(), vec!["github.com".into()])
    }

    fn gw_with(approvals: Option<EgressApprovalTx>, real_world: RealWorldPolicy, allow_suffixes: Vec<String>) -> GatewayConfig {
        GatewayConfig {
            token: "t".into(),
            key: "k".into(),
            allow_suffixes,
            stats: Arc::new(GatewayStats::default()),
            approvals,
            approved: Arc::new(Mutex::new(HashSet::new())),
            host_addrs: Arc::new(HashSet::new()),
            real_world: Arc::new(real_world),
        }
    }

    async fn run_request(config: GatewayConfig, req: &str) -> String {
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            let _ = handle(server, config).await;
        });
        client.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match client.read(&mut byte).await {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    buf.push(byte[0]);
                }
                Err(_) => break,
            }
        }
        let _ = task.await;
        String::from_utf8(buf).unwrap()
    }

    #[tokio::test]
    async fn unlisted_host_denied_by_user_is_refused() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<EgressApproval>();
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let _ = req.reply.send(false);
            }
        });
        // example.com is not on the allowlist → asked → user denies → refused
        // (before any DNS resolution, so no network is touched).
        assert_eq!(run_request(gw(Some(tx)), "t k example.com 443\n").await, "ERR egress denied by user");
    }

    #[tokio::test]
    async fn approved_unlisted_host_is_remembered() {
        use std::sync::atomic::AtomicU64;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<EgressApproval>();
        let asks = Arc::new(AtomicU64::new(0));
        let counter = asks.clone();
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = req.reply.send(true);
            }
        });
        let config = gw(Some(tx));
        // localhost isn't allowlisted and resolves only to loopback (forbidden), so
        // after approval the connection is refused at resolution — but approval DID
        // happen, and the host is remembered so the second request does not re-ask.
        assert_eq!(run_request(config.clone(), "t k localhost 80\n").await, "ERR unresolved or forbidden");
        assert_eq!(run_request(config.clone(), "t k localhost 80\n").await, "ERR unresolved or forbidden");
        assert_eq!(asks.load(Ordering::Relaxed), 1, "second request must not re-ask an approved host");
    }

    #[tokio::test]
    async fn unlisted_host_without_approver_is_denied() {
        assert_eq!(run_request(gw(None), "t k example.com 443\n").await, "ERR host not allowed");
    }

    #[tokio::test]
    async fn real_world_host_without_approver_is_denied_even_when_allow_public() {
        let config = gw_with(None, RealWorldPolicy::defaults(), vec!["*".into()]);
        let stats = config.stats.clone();
        // `"*"` normally allows any public host; real-world hosts are checked first.
        assert_eq!(run_request(config, "t k api.stripe.com 443\n").await, "ERR real-world host requires a human");
        assert_eq!(stats.denied_real_world.load(Ordering::Relaxed), 1);
        assert_eq!(stats.denied_policy.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn real_world_host_with_approver_asks_every_time_and_is_not_remembered() {
        use std::sync::atomic::AtomicU64;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<EgressApproval>();
        let asks = Arc::new(AtomicU64::new(0));
        let counter = asks.clone();
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = req.reply.send(true);
            }
        });
        // A real-world host that resolves only to loopback: approval happens, then
        // resolution refuses it (no network is touched). Every request asks again.
        let mut policy = RealWorldPolicy::defaults();
        policy.hosts = vec!["localhost".into()];
        let config = gw_with(Some(tx), policy, vec!["*".into()]);
        assert_eq!(run_request(config.clone(), "t k localhost 80\n").await, "ERR unresolved or forbidden");
        assert_eq!(run_request(config.clone(), "t k localhost 80\n").await, "ERR unresolved or forbidden");
        assert_eq!(asks.load(Ordering::Relaxed), 2, "real-world hosts are never remembered");
        assert!(config.approved.lock().await.is_empty(), "real-world approval must not enter the session allowlist");
    }
}
