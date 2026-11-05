//! Host side of the guest channel: one unix socket to the VM's transport,
//! carrying framed [`HostMsg`]/[`GuestMsg`] traffic.
//!
//! Both providers expose the guest's single channel as a host unix socket, so
//! this is the only transport code there is:
//!
//! * Firecracker: `vsock` uds + the `CONNECT <port>\n` handshake
//!   (`<run>/vsock.sock`). The guest listens on AF_VSOCK `VSOCK_PORT`.
//! * QEMU: `-chardev socket,...,server=on` + virtio-serial, so the guest reads
//!   `/dev/vport0p1` (`<run>/chan.sock`). No handshake.
//!
//! Read and write halves are separate fds: a command streams output while the
//! caller writes stdin from another thread.

use crate::proto::{decode, encode, GuestMsg, HostMsg};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Guest listens on AF_VSOCK; the host socket needs the CONNECT preamble.
    Vsock { port: u32 },
    /// Guest uses a virtio-serial port; the host socket is transparent.
    Serial,
}

impl Transport {
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Vsock { .. } => "vsock",
            Transport::Serial => "virtio-serial",
        }
    }
}

pub struct Channel {
    w: UnixStream,
    r: UnixStream,
    /// Bytes read but not yet a complete frame, and frames decoded ahead of the
    /// caller (one read may yield several). Behind a mutex so `recv` can take
    /// `&self`: the pool hands the same `Arc<Channel>` to a command's reader
    /// while the caller writes stdin from another thread.
    rbuf: std::sync::Mutex<(Vec<u8>, std::collections::VecDeque<GuestMsg>)>,
    transport: Transport,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel").field("transport", &self.transport).finish()
    }
}

impl Channel {
    /// Wrap a connected socket. `port` is the vsock port for the handshake.
    pub fn from_stream(stream: UnixStream, transport: Transport) -> Result<Channel, String> {
        if let Transport::Vsock { port } = transport {
            let mut w = stream.try_clone().map_err(|e| format!("clone channel: {e}"))?;
            w.set_write_timeout(Some(Duration::from_secs(5))).ok();
            w.write_all(format!("CONNECT {port}\n").as_bytes()).map_err(|e| format!("vsock CONNECT: {e}"))?;
            let mut r = stream.try_clone().map_err(|e| format!("clone channel: {e}"))?;
            r.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            while !line.ends_with(b"\n") {
                match r.read(&mut b) {
                    Ok(0) => return Err("vsock host socket closed during CONNECT".into()),
                    Ok(_) => line.push(b[0]),
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(format!("vsock CONNECT reply: {e}")),
                }
                if line.len() > 64 {
                    return Err("vsock CONNECT reply too long".into());
                }
            }
            let text = String::from_utf8_lossy(&line).trim().to_string();
            if !text.starts_with("OK") {
                return Err(format!("vsock CONNECT refused: {text}"));
            }
        }
        let w = stream.try_clone().map_err(|e| format!("clone channel: {e}"))?;
        Ok(Channel { w, r: stream, rbuf: Default::default(), transport })
    }

    /// Connect to `<run>/chan.sock` (QEMU) or `<run>/vsock.sock` (Firecracker),
    /// retrying until the VM has created it.
    pub fn connect(path: &std::path::Path, transport: Transport, wait: Duration) -> Result<Channel, String> {
        let deadline = Instant::now() + wait;
        loop {
            match UnixStream::connect(path) {
                Ok(s) => match Channel::from_stream(s, transport) {
                    Ok(c) => return Ok(c),
                    // Firecracker answers CONNECT and closes it while the guest
                    // agent is still booting: retry the *handshake*, not just
                    // the connect.
                    Err(e) if Instant::now() < deadline && e.contains("closed") => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if Instant::now() < deadline && matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(format!("connect {}: {e}", path.display())),
            }
        }
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    pub fn send(&self, m: &HostMsg) -> Result<(), String> {
        let bytes = encode(m)?;
        let mut w = &self.w;
        w.write_all(&bytes).and_then(|_| w.flush()).map_err(|e| format!("channel write: {e}"))
    }

    /// Next guest frame. Ok(None) when nothing arrived within `timeout`
    /// (or the peer went away: `eof()` tells the two apart).
    pub fn recv(&self, timeout: Duration) -> Result<Option<GuestMsg>, String> {
        let mut st = self.rbuf.lock().unwrap();
        if let Some(m) = st.1.pop_front() {
            return Ok(Some(m));
        }
        let deadline = Instant::now() + timeout;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            self.r.set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok();
            // `Read for &UnixStream`: the fd is shared, the read state is not.
            match (&self.r).read(&mut chunk) {
                Ok(0) => {
                    // Closed. Any buffered frames are still valid.
                    let (frames, used) = decode::<GuestMsg>(&st.0)?;
                    st.0.drain(..used);
                    st.1.extend(frames);
                    if let Some(m) = st.1.pop_front() {
                        return Ok(Some(m));
                    }
                    return Err("guest channel closed".into());
                }
                Ok(n) => {
                    st.0.extend_from_slice(&chunk[..n]);
                    let (frames, used) = decode::<GuestMsg>(&st.0)?;
                    if used > 0 {
                        st.0.drain(..used);
                        st.1.extend(frames);
                        return Ok(st.1.pop_front());
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(None),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("channel read: {e}")),
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    /// Read one frame, waiting up to `timeout`; Err on timeout.
    pub fn expect(&self, timeout: Duration, what: &str) -> Result<GuestMsg, String> {
        self.recv(timeout)?.ok_or_else(|| format!("timed out waiting for {what}"))
    }

    /// Ask for a fresh Hello (used as a liveness probe).
    pub fn ping(&self, timeout: Duration) -> Result<(), String> {
        self.send(&HostMsg::Ping { id: 0 })?;
        loop {
            match self.expect(timeout, "Pong")? {
                GuestMsg::Pong { .. } => return Ok(()),
                _ => continue,
            }
        }
    }

    /// Send `Shutdown` and close. Takes `&self` like the readers, so a cached
    /// `Arc<Channel>` is enough to end a session.
    pub fn shutdown(&self) {
        let _ = self.send(&HostMsg::Shutdown);
        let _ = self.w.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::FileBlob;

    /// A paired guest that answers like the agent would (no VM needed).
    fn pair() -> (Channel, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        (Channel::from_stream(a, Transport::Serial).unwrap(), b)
    }

    #[test]
    fn frames_flow_both_ways_with_timeouts() {
        let (ch, mut guest) = pair();
        ch.send(&HostMsg::Exec { id: 1, script: "echo hi".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 0 }).unwrap();
        let mut got = Vec::new();
        std::thread::sleep(Duration::from_millis(30));
        guest.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 4096];
        let n = guest.read(&mut buf).unwrap();
        got.extend_from_slice(&buf[..n]);
        let (frames, _) = decode::<HostMsg>(&got).unwrap();
        assert!(matches!(frames[0], HostMsg::Exec { id: 1, .. }));

        // Timeouts are Ok(None), not an error.
        assert!(ch.recv(Duration::from_millis(20)).unwrap().is_none());

        guest.write_all(&encode(&GuestMsg::Out { id: 1, data: "aGk=".into() }).unwrap()).unwrap();
        match ch.expect(Duration::from_secs(2), "out").unwrap() {
            GuestMsg::Out { id, data } => {
                assert_eq!(id, 1);
                assert_eq!(data, "aGk=");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn closed_channel_reports_eof_and_keeps_buffered_frames() {
        let (ch, mut guest) = pair();
        let mut bytes = encode(&GuestMsg::Files { id: 3, files: vec![FileBlob { path: "a".into(), data: String::new(), mode: 0o644 }] }).unwrap();
        bytes.extend(encode(&GuestMsg::Exit { id: 3, code: Some(0), signal: None }).unwrap());
        guest.write_all(&bytes).unwrap();
        drop(guest);
        let mut seen = Vec::new();
        loop {
            match ch.recv(Duration::from_millis(200)) {
                Ok(Some(m)) => seen.push(m),
                Ok(None) => break,
                Err(e) => {
                    assert!(e.contains("closed"), "{e}");
                    break;
                }
            }
        }
        assert_eq!(seen.len(), 2, "both buffered frames survive the close: {seen:?}");
    }

    #[test]
    fn vsock_handshake_rejects_garbage() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 32];
            let n = b.read(&mut buf).unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("CONNECT 5000"));
            b.write_all(b"ERR no such port\n").unwrap();
            b
        });
        let e = Channel::from_stream(a, Transport::Vsock { port: 5000 }).unwrap_err();
        assert!(e.contains("refused"), "{e}");
        let _ = t.join();
    }
}
