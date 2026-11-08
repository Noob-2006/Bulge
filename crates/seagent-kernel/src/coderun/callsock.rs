//! The endpoint a code-mode script reaches back through (`seagent-call`, `seagent_call()`).
//!
//! * **Unix** (Linux, macOS, Android) — unchanged: a one-shot unix socket
//!   `<runtime>/<prefix>-<16 hex>.sock`; `SEAGENT_CALL_SOCK` is its path.
//! * **Windows** — std has no unix sockets there, so the endpoint is a loopback TCP listener on
//!   `127.0.0.1:<ephemeral port>` and `SEAGENT_CALL_SOCK` is `tcp:127.0.0.1:<port>`. Unlike a
//!   0600 socket, a loopback port is reachable by every local account, so the per-call random
//!   token every request carries (`SEAGENT_CALL_TOKEN`, 32 random bytes, checked by
//!   `coderun::serve` before anything runs) is the handshake that keeps other users out.
//!
//! Clients (the Rust `client`, the Python runner) pick the transport from the value's
//! `tcp:` prefix, so one environment variable works everywhere.

use std::io::{self, Read, Write};
use std::path::Path;

/// `SEAGENT_CALL_SOCK` values with this prefix name a loopback TCP endpoint.
pub const TCP_PREFIX: &str = "tcp:";

/// A bound nested-call endpoint.
pub struct CallListener {
    #[cfg(unix)]
    inner: std::os::unix::net::UnixListener,
    #[cfg(not(unix))]
    inner: std::net::TcpListener,
    addr: String,
}

/// One accepted (or client) connection.
pub enum CallConn {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Tcp(std::net::TcpStream),
}

impl CallListener {
    /// Bind a fresh endpoint (`prefix` names the socket file on Unix: `call`, `kernel`).
    #[cfg(unix)]
    pub fn bind(runtime_dir: &Path, prefix: &str) -> Result<CallListener, String> {
        let sock = runtime_dir.join(format!("{prefix}-{}.sock", crate::util::random_hex(8)));
        let inner = std::os::unix::net::UnixListener::bind(&sock).map_err(|e| format!("cannot bind {}: {e}", sock.display()))?;
        Ok(CallListener { inner, addr: sock.to_string_lossy().into_owned() })
    }

    /// Bind a fresh endpoint: loopback TCP on an ephemeral port (see the module docs).
    #[cfg(not(unix))]
    pub fn bind(_runtime_dir: &Path, _prefix: &str) -> Result<CallListener, String> {
        let inner = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("cannot bind a loopback port for nested calls: {e}"))?;
        let port = inner.local_addr().map_err(|e| e.to_string())?.port();
        Ok(CallListener { inner, addr: format!("{TCP_PREFIX}127.0.0.1:{port}") })
    }

    /// The value for `SEAGENT_CALL_SOCK`.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Wait for the next client.
    pub fn accept(&self) -> io::Result<CallConn> {
        #[cfg(unix)]
        {
            self.inner.accept().map(|(s, _)| CallConn::Unix(s))
        }
        #[cfg(not(unix))]
        {
            self.inner.accept().map(|(s, _)| CallConn::Tcp(s))
        }
    }
}

/// Connect to the endpoint named by a `SEAGENT_CALL_SOCK` value. Used to wake a blocked
/// `accept` too.
pub fn connect(addr: &str) -> io::Result<CallConn> {
    if let Some(hp) = addr.strip_prefix(TCP_PREFIX) {
        return std::net::TcpStream::connect(hp).map(CallConn::Tcp);
    }
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(addr).map(CallConn::Unix)
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("unix sockets are not available on {}: SEAGENT_CALL_SOCK must be `{TCP_PREFIX}host:port`, got {addr}", std::env::consts::OS)))
    }
}

/// Remove what the endpoint left on disk (the Unix socket file; nothing for TCP).
pub fn cleanup(addr: &str) {
    if !addr.starts_with(TCP_PREFIX) {
        let _ = std::fs::remove_file(addr);
    }
}

impl CallConn {
    pub fn try_clone(&self) -> io::Result<CallConn> {
        match self {
            #[cfg(unix)]
            CallConn::Unix(s) => s.try_clone().map(CallConn::Unix),
            CallConn::Tcp(s) => s.try_clone().map(CallConn::Tcp),
        }
    }
}

impl Read for CallConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            CallConn::Unix(s) => s.read(buf),
            CallConn::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for CallConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            CallConn::Unix(s) => s.write(buf),
            CallConn::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            CallConn::Unix(s) => s.flush(),
            CallConn::Tcp(s) => s.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    #[test]
    fn endpoint_round_trip_and_cleanup() {
        let d = seagent_core::tmp::TempDir::new("seagent-callsock");
        let l = CallListener::bind(d.path(), "call").unwrap();
        let addr = l.addr().to_string();
        assert_eq!(addr.starts_with(TCP_PREFIX), cfg!(not(unix)), "{addr}");
        let srv = std::thread::spawn(move || {
            let c = l.accept().unwrap();
            let mut w = c.try_clone().unwrap();
            let mut line = String::new();
            BufReader::new(c).read_line(&mut line).unwrap();
            w.write_all(format!("echo {line}").as_bytes()).unwrap();
        });
        let mut c = connect(&addr).unwrap();
        c.write_all(b"hi\n").unwrap();
        let mut reply = String::new();
        BufReader::new(c).read_line(&mut reply).unwrap();
        assert_eq!(reply, "echo hi\n");
        srv.join().unwrap();
        cleanup(&addr);
        if cfg!(unix) {
            assert!(!Path::new(&addr).exists());
        }
    }

    #[test]
    fn tcp_prefix_is_honoured_on_every_os() {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(connect(&format!("{TCP_PREFIX}127.0.0.1:{port}")).is_ok());
    }
}
