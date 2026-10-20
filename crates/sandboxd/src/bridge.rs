//! Guest-side egress bridge.
//!
//! The guest has no network interface. This bridge is a tiny HTTPS (CONNECT)
//! proxy on loopback that carries each tunnel over vsock to the host's two-key
//! egress gateway, prefixing the two session secrets. Tools reach it through the
//! `HTTPS_PROXY` environment variable; without it, nothing in the guest can talk
//! to the outside world.
//!
//! Only CONNECT (TLS) is proxied — the overwhelmingly common case (package
//! registries, git-over-https, APIs). Plain-HTTP proxying is intentionally not
//! supported.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_vsock::{VsockAddr, VsockStream};

use bulge_proto::msg::GATEWAY_VSOCK_PORT;

/// Host CID in the vsock address space (the VMM/host is always CID 2).
const HOST_CID: u32 = 2;
/// Loopback address the proxy listens on.
pub const PROXY_ADDR: &str = "127.0.0.1:3128";
/// Value to export as HTTPS_PROXY / HTTP_PROXY.
pub const PROXY_URL: &str = "http://127.0.0.1:3128";

/// Start the loopback CONNECT proxy. `token`/`key` are the two egress secrets the
/// host gateway will check. Runs until the listener errors.
pub async fn serve(token: String, key: String) -> std::io::Result<()> {
    let listener = TcpListener::bind(PROXY_ADDR).await?;
    loop {
        let (client, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let (token, key) = (token.clone(), key.clone());
        tokio::spawn(async move {
            let _ = handle(client, token, key).await;
        });
    }
}

async fn handle(mut client: TcpStream, token: String, key: String) -> std::io::Result<()> {
    let head = read_head(&mut client).await?;
    let Some((host, port)) = parse_connect(&head) else {
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await;
        return Ok(());
    };

    let mut up = match VsockStream::connect(VsockAddr::new(HOST_CID, GATEWAY_VSOCK_PORT)).await {
        Ok(stream) => stream,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Ok(());
        }
    };
    up.write_all(format!("{token} {key} {host} {port}\n").as_bytes()).await?;

    // The gateway answers with a single status line.
    let reply = read_line(&mut up).await.unwrap_or_default();
    if reply.trim() != "OK" {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return Ok(());
    }
    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
    Ok(())
}

/// Read the request head up to the blank line that ends it (bounded).
async fn read_head(client: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while client.read(&mut byte).await? == 1 {
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.len() > 8192 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Extract `host`, `port` from a `CONNECT host:port HTTP/1.1` request line.
fn parse_connect(head: &str) -> Option<(String, u16)> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let authority = parts.next()?;
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() || host.contains('/') {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

async fn read_line(stream: &mut VsockStream) -> Option<String> {
    let mut buf = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() > 256 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    String::from_utf8(buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_requests() {
        assert_eq!(parse_connect("CONNECT example.com:443 HTTP/1.1\r\n\r\n"), Some(("example.com".into(), 443)));
        assert_eq!(parse_connect("connect h:80 HTTP/1.1\r\n"), Some(("h".into(), 80)));
        assert_eq!(parse_connect("GET http://x/ HTTP/1.1\r\n"), None);
        assert_eq!(parse_connect("CONNECT noport HTTP/1.1\r\n"), None);
        assert_eq!(parse_connect("CONNECT h:bad HTTP/1.1\r\n"), None);
    }
}
