//! Host side of the guest channel: one byte stream to the VM's transport,
//! carrying framed [`HostMsg`]/[`GuestMsg`] traffic.
//!
//! Every provider exposes the guest's single channel as one host stream, so
//! this is the only transport code there is:
//!
//! * Firecracker: `vsock` uds + the `CONNECT <port>\n` handshake
//!   (`<run>/vsock.sock`). The guest listens on AF_VSOCK `VSOCK_PORT`.
//! * QEMU: `-chardev socket,...,server=on` + virtio-serial, so the guest reads
//!   `/dev/vport0p1` (`<run>/chan.sock`). No handshake. On Windows (no unix
//!   sockets for QEMU) the chardev is a TCP server on 127.0.0.1 and
//!   `<run>/chan.sock` is a small file naming its port ([`Endpoint`]).
//! * vfkit (Apple Virtualization.framework): `virtio-vsock,…,listen` proxies
//!   a unix socket straight to the guest's vsock port — no preface
//!   ([`Transport::VsockProxy`]).
//! * VirtualBox / Hyper-V: the guest's second UART (`/dev/ttyS1`), served by the
//!   hypervisor as a unix socket (VirtualBox on Linux/macOS) or a named pipe
//!   (Windows) — [`Transport::Uart`].
//! * Android AVF (crosvm): a direct AF_VSOCK connection to the guest's CID.
//!
//! Read and write halves are separate handles: a command streams output while the
//! caller writes stdin from another thread.

use crate::proto::{decode, encode, GuestMsg, HostMsg};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Guest listens on AF_VSOCK; the host socket needs the CONNECT preamble (Firecracker).
    Vsock { port: u32 },
    /// Guest uses a virtio-serial port; the host socket is transparent.
    Serial,
    /// Guest listens on AF_VSOCK and the VMM (vfkit, crosvm) connects the host stream
    /// straight to that port: no preamble.
    VsockProxy { port: u32 },
    /// Guest uses its second 16550 UART (`/dev/ttyS1`): VirtualBox, Hyper-V COM ports.
    Uart,
}

impl Transport {
    /// What the guest is told on its kernel command line (`seagent.channel=`).
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Vsock { .. } | Transport::VsockProxy { .. } => "vsock",
            Transport::Serial => "virtio-serial",
            Transport::Uart => "uart",
        }
    }
}

/// One connected host-side stream. Linux keeps its unix socket (same fd, same syscalls);
/// the other variants exist only where a VMM cannot offer one.
#[derive(Debug)]
pub enum Stream {
    #[cfg(unix)]
    Unix(UnixStream),
    /// QEMU's `-chardev socket,host=127.0.0.1,…` on Windows.
    Tcp(TcpStream),
    /// A hypervisor-served named pipe (VirtualBox / Hyper-V COM port on Windows).
    #[cfg(windows)]
    Pipe(pipe::Pipe),
}

impl Stream {
    pub fn connect_unix(path: &Path) -> std::io::Result<Stream> {
        #[cfg(unix)]
        {
            UnixStream::connect(path).map(Stream::Unix)
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(ErrorKind::Unsupported, format!("{}: unix sockets are not available to VMMs on this OS", path.display())))
        }
    }

    pub fn connect_tcp(addr: SocketAddr) -> std::io::Result<Stream> {
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        s.set_nodelay(true).ok();
        Ok(Stream::Tcp(s))
    }

    /// Connect AF_VSOCK to `cid:port` (Android AVF: the host talks to the guest directly).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn connect_vsock(cid: u32, port: u32) -> std::io::Result<Stream> {
        use std::os::fd::FromRawFd;
        // SAFETY: plain socket calls; the fd is owned by the UnixStream on success (a stream
        // socket of any family supports the read/write/timeout/shutdown calls it makes).
        unsafe {
            let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut a: libc::sockaddr_vm = std::mem::zeroed();
            a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            a.svm_cid = cid;
            a.svm_port = port;
            if libc::connect(fd, (&a as *const libc::sockaddr_vm).cast(), std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t) != 0 {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            Ok(Stream::Unix(UnixStream::from_raw_fd(fd)))
        }
    }

    /// A connected pair (tests, in-process fakes).
    pub fn pair() -> std::io::Result<(Stream, Stream)> {
        #[cfg(unix)]
        {
            UnixStream::pair().map(|(a, b)| (Stream::Unix(a), Stream::Unix(b)))
        }
        #[cfg(not(unix))]
        {
            let l = std::net::TcpListener::bind("127.0.0.1:0")?;
            let a = TcpStream::connect(l.local_addr()?)?;
            let (b, _) = l.accept()?;
            Ok((Stream::Tcp(a), Stream::Tcp(b)))
        }
    }

    pub fn try_clone(&self) -> std::io::Result<Stream> {
        Ok(match self {
            #[cfg(unix)]
            Stream::Unix(s) => Stream::Unix(s.try_clone()?),
            Stream::Tcp(s) => Stream::Tcp(s.try_clone()?),
            #[cfg(windows)]
            Stream::Pipe(p) => Stream::Pipe(p.try_clone()?),
        })
    }
    pub fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.set_read_timeout(t),
            Stream::Tcp(s) => s.set_read_timeout(t),
            #[cfg(windows)]
            Stream::Pipe(p) => p.set_read_timeout(t),
        }
    }
    pub fn set_write_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.set_write_timeout(t),
            Stream::Tcp(s) => s.set_write_timeout(t),
            #[cfg(windows)]
            Stream::Pipe(_) => Ok(()),
        }
    }
    pub fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.shutdown(how),
            Stream::Tcp(s) => s.shutdown(how),
            #[cfg(windows)]
            Stream::Pipe(p) => p.close(),
        }
    }
}

impl Read for &Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match *self {
            #[cfg(unix)]
            Stream::Unix(s) => (&*s).read(buf),
            Stream::Tcp(s) => (&*s).read(buf),
            #[cfg(windows)]
            Stream::Pipe(p) => p.read(buf),
        }
    }
}

impl Write for &Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match *self {
            #[cfg(unix)]
            Stream::Unix(s) => (&*s).write(buf),
            Stream::Tcp(s) => (&*s).write(buf),
            #[cfg(windows)]
            Stream::Pipe(p) => p.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match *self {
            #[cfg(unix)]
            Stream::Unix(s) => (&*s).flush(),
            Stream::Tcp(s) => (&*s).flush(),
            #[cfg(windows)]
            Stream::Pipe(_) => Ok(()),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        (&*self).flush()
    }
}

/// Where a VMM serves one host-side socket (guest channel, QMP, a text port).
///
/// The *name* of an endpoint is always a path in the VM's private run dir. On unix that path
/// is the unix socket itself — exactly what Linux always used. On Windows a VMM cannot bind a
/// unix socket, so the path is a one-line record (`tcp:127.0.0.1:<port>` or
/// `pipe:\\.\pipe\<name>`) written when the VM is configured and read by whoever connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp(SocketAddr),
    Pipe(String),
}

/// A port on host loopback nobody listens on right now (the VMM binds it a moment later).
pub fn free_loopback_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).map_err(|e| format!("no free loopback port: {e}"))
}

impl Endpoint {
    /// The endpoint a VMM should serve for `path`: the unix socket itself where the OS has
    /// them, else a free loopback port recorded in `path`.
    pub fn allocate(path: &Path) -> Result<Endpoint, String> {
        let _ = std::fs::remove_file(path);
        if cfg!(unix) {
            return Ok(Endpoint::Unix(path.to_path_buf()));
        }
        let ep = Endpoint::Tcp(SocketAddr::from(([127, 0, 0, 1], free_loopback_port()?)));
        ep.record(path)?;
        Ok(ep)
    }

    /// A named pipe endpoint (Windows), recorded in `path`.
    pub fn allocate_pipe(path: &Path, name: &str) -> Result<Endpoint, String> {
        let ep = Endpoint::Pipe(format!(r"\\.\pipe\{name}"));
        ep.record(path)?;
        Ok(ep)
    }

    fn record(&self, path: &Path) -> Result<(), String> {
        let line = match self {
            Endpoint::Unix(p) => format!("unix:{}", p.display()),
            Endpoint::Tcp(a) => format!("tcp:{a}"),
            Endpoint::Pipe(n) => format!("pipe:{n}"),
        };
        std::fs::write(path, format!("{line}\n")).map_err(|e| format!("record endpoint {}: {e}", path.display()))
    }

    /// Where to connect for `path`. NotFound while the VM has not created it yet.
    pub fn locate(path: &Path) -> std::io::Result<Endpoint> {
        if cfg!(unix) {
            return Ok(Endpoint::Unix(path.to_path_buf()));
        }
        let s = std::fs::read_to_string(path)?;
        let s = s.trim();
        if let Some(a) = s.strip_prefix("tcp:") {
            return a.parse().map(Endpoint::Tcp).map_err(|e| std::io::Error::new(ErrorKind::InvalidData, format!("{}: {e}", path.display())));
        }
        if let Some(n) = s.strip_prefix("pipe:") {
            return Ok(Endpoint::Pipe(n.to_string()));
        }
        Err(std::io::Error::new(ErrorKind::InvalidData, format!("{}: not an endpoint record", path.display())))
    }

    pub fn connect(&self) -> std::io::Result<Stream> {
        match self {
            Endpoint::Unix(p) => Stream::connect_unix(p),
            Endpoint::Tcp(a) => Stream::connect_tcp(*a),
            #[cfg(windows)]
            Endpoint::Pipe(n) => pipe::Pipe::open(n).map(Stream::Pipe),
            #[cfg(not(windows))]
            Endpoint::Pipe(n) => Err(std::io::Error::new(ErrorKind::Unsupported, format!("{n}: named pipes exist on Windows only"))),
        }
    }

    /// QEMU `-chardev` spec serving this endpoint.
    pub fn qemu_chardev(&self, id: &str) -> String {
        match self {
            Endpoint::Unix(p) => format!("socket,id={id},path={},server=on,wait=off", p.display()),
            // `nodelay=on`: QEMU leaves Nagle on for a TCP chardev unless asked, so a small
            // guest frame sent right behind another (`Exit` after the last `Out`) could wait for
            // the host's delayed ACK (up to 200 ms on Windows). The host end sets TCP_NODELAY
            // too (`Stream::connect_tcp`); a unix socket has no such thing.
            Endpoint::Tcp(a) => format!("socket,id={id},host={},port={},server=on,wait=off,nodelay=on", a.ip(), a.port()),
            Endpoint::Pipe(n) => format!("pipe,id={id},path={}", n.trim_start_matches(r"\\.\pipe\")),
        }
    }

    /// QEMU `-qmp` / `-monitor` spec serving this endpoint.
    pub fn qemu_monitor(&self) -> String {
        match self {
            Endpoint::Unix(p) => format!("unix:{},server=on,wait=off", p.display()),
            Endpoint::Tcp(a) => format!("tcp:{a},server=on,wait=off"),
            Endpoint::Pipe(n) => format!("pipe:{}", n.trim_start_matches(r"\\.\pipe\")),
        }
    }

    /// Listen on this endpoint (in-process fakes standing in for a VMM).
    pub fn listen(&self) -> std::io::Result<Listener> {
        match self {
            #[cfg(unix)]
            Endpoint::Unix(p) => std::os::unix::net::UnixListener::bind(p).map(Listener::Unix),
            Endpoint::Tcp(a) => std::net::TcpListener::bind(a).map(Listener::Tcp),
            _ => Err(std::io::Error::new(ErrorKind::Unsupported, "cannot listen on this endpoint here")),
        }
    }
}

/// The listening side of an [`Endpoint`] (test fakes).
#[derive(Debug)]
pub enum Listener {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
    Tcp(std::net::TcpListener),
}

impl Listener {
    pub fn accept(&self) -> std::io::Result<Stream> {
        match self {
            #[cfg(unix)]
            Listener::Unix(l) => l.accept().map(|(s, _)| Stream::Unix(s)),
            Listener::Tcp(l) => l.accept().map(|(s, _)| Stream::Tcp(s)),
        }
    }
    pub fn set_nonblocking(&self, on: bool) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Listener::Unix(l) => l.set_nonblocking(on),
            Listener::Tcp(l) => l.set_nonblocking(on),
        }
    }
}

impl Stream {
    pub fn set_nonblocking(&self, on: bool) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.set_nonblocking(on),
            Stream::Tcp(s) => s.set_nonblocking(on),
            #[cfg(windows)]
            Stream::Pipe(_) => Ok(()),
        }
    }
}

#[cfg(windows)]
pub mod pipe {
    //! Client end of a hypervisor-served named pipe (`\\.\pipe\…`). Synchronous pipe handles
    //! serialise every I/O on the file object, so a reader blocked in `ReadFile` would stall
    //! the writer; reads therefore only happen once `PeekNamedPipe` says bytes are waiting,
    //! which also gives `set_read_timeout` its meaning.
    use std::fs::File;
    use std::io::{ErrorKind, Read, Write};
    use std::os::windows::io::AsRawHandle;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    pub struct Pipe {
        file: File,
        timeout_ms: Arc<AtomicU64>,
        closed: Arc<AtomicBool>,
    }

    impl Pipe {
        pub fn open(name: &str) -> std::io::Result<Pipe> {
            let file = std::fs::OpenOptions::new().read(true).write(true).open(name)?;
            Ok(Pipe { file, timeout_ms: Arc::new(AtomicU64::new(0)), closed: Arc::new(AtomicBool::new(false)) })
        }
        pub fn try_clone(&self) -> std::io::Result<Pipe> {
            Ok(Pipe { file: self.file.try_clone()?, timeout_ms: self.timeout_ms.clone(), closed: self.closed.clone() })
        }
        pub fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
            self.timeout_ms.store(t.map(|d| d.as_millis().max(1) as u64).unwrap_or(0), Ordering::SeqCst);
            Ok(())
        }
        pub fn close(&self) -> std::io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn available(&self) -> std::io::Result<u32> {
            let mut avail = 0u32;
            // SAFETY: peek without a buffer, only the byte count.
            let ok = unsafe { windows_sys::Win32::System::Pipes::PeekNamedPipe(self.file.as_raw_handle() as isize, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) };
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                // ERROR_BROKEN_PIPE: the hypervisor closed its end (VM gone) = EOF.
                return if e.raw_os_error() == Some(109) { Ok(u32::MAX) } else { Err(e) };
            }
            Ok(avail)
        }
        pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let t = self.timeout_ms.load(Ordering::SeqCst);
            let deadline = (t > 0).then(|| Instant::now() + Duration::from_millis(t));
            loop {
                if self.closed.load(Ordering::SeqCst) {
                    return Ok(0);
                }
                match self.available()? {
                    u32::MAX => return Ok(0),
                    0 => {}
                    n => {
                        let want = buf.len().min(n as usize);
                        return (&self.file).read(&mut buf[..want]);
                    }
                }
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    return Err(std::io::Error::new(ErrorKind::TimedOut, "named pipe read timed out"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
            if self.closed.load(Ordering::SeqCst) {
                return Err(std::io::Error::new(ErrorKind::BrokenPipe, "channel closed"));
            }
            (&self.file).write(buf)
        }
    }
}

pub struct Channel {
    w: Stream,
    r: Stream,
    /// Bytes read but not yet a complete frame, and frames decoded ahead of the
    /// caller (one read may yield several). Behind a mutex so `recv` can take
    /// `&self`: the pool hands the same `Arc<Channel>` to a command's reader
    /// while the caller writes stdin from another thread.
    rbuf: std::sync::Mutex<(Vec<u8>, std::collections::VecDeque<GuestMsg>)>,
    transport: Transport,
    /// A UART channel (COM2) also carries whatever the firmware printed before the agent took
    /// the port (UEFI writes terminal escapes to every serial port): until the first frame
    /// decodes, bytes that cannot start a frame are skipped ([`resync_skip`]). Every other
    /// transport is strict from its first byte, as it always was.
    synced: std::sync::atomic::AtomicBool,
}

/// How many leading bytes of `buf` to drop so it starts at something that can be a frame
/// (a length within [`crate::proto::MAX_FRAME`] followed by `{`); keeps a possible partial
/// header at the end.
pub fn resync_skip(buf: &[u8]) -> usize {
    let plausible = |i: usize| {
        let len = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        len <= crate::proto::MAX_FRAME && buf[i + 4] == b'{'
    };
    (1..buf.len()).find(|&i| i + 5 <= buf.len() && plausible(i)).unwrap_or(buf.len().saturating_sub(4).max(1).min(buf.len()))
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel").field("transport", &self.transport).finish()
    }
}

impl Channel {
    /// Wrap a connected socket. `port` is the vsock port for the handshake.
    #[cfg(unix)]
    pub fn from_unix(stream: UnixStream, transport: Transport) -> Result<Channel, String> {
        Channel::from_stream(Stream::Unix(stream), transport)
    }

    /// Wrap a connected stream. `Transport::Vsock { port }` performs Firecracker's
    /// `CONNECT <port>\n` handshake first.
    pub fn from_stream(stream: Stream, transport: Transport) -> Result<Channel, String> {
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
        Ok(Channel { w, r: stream, rbuf: Default::default(), transport, synced: std::sync::atomic::AtomicBool::new(transport != Transport::Uart) })
    }

    /// Connect to `<run>/chan.sock` (QEMU) or `<run>/vsock.sock` (Firecracker),
    /// retrying until the VM has created it. On Windows `path` is the endpoint record
    /// ([`Endpoint::locate`]).
    pub fn connect(path: &std::path::Path, transport: Transport, wait: Duration) -> Result<Channel, String> {
        let deadline = Instant::now() + wait;
        loop {
            match Endpoint::locate(path).and_then(|ep| ep.connect()) {
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
                // ERROR_PIPE_BUSY (231): a hypervisor's named-pipe server between two clients
                // (e.g. right after another process let go of it) — retry like a refused socket.
                Err(e) if Instant::now() < deadline && (matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) || (cfg!(windows) && e.raw_os_error() == Some(231))) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(format!("connect {}: {e}", path.display())),
            }
        }
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Mutual authentication on a channel other local processes can reach (Windows QEMU's
    /// loopback TCP chardev), with the per-boot `key` the provider gave the guest through
    /// fw_cfg. The guest's `Hello` carries a nonce; the host answers [`HostMsg::Auth`] with its
    /// proof and its own nonce; the guest answers [`GuestMsg::Auth`]. Nothing else is trusted
    /// before both proofs check: a process that grabbed the port first cannot pass for the
    /// guest (it has no key), and one that reaches the guest cannot drive it (the agent refuses
    /// every frame until `Auth` verified). The `Hello` is put back in front of the queue, so the
    /// caller reads it exactly as on an unauthenticated channel.
    pub fn authenticate(&self, key: &[u8], wait: Duration) -> Result<(), String> {
        // Wait for the Hello; after a second of silence, poke the guest (an unauthenticated
        // guest answers any frame with its Hello again) — the Hello may have gone to a process
        // that held the port before us.
        let deadline = Instant::now() + wait;
        let hello = loop {
            match self.recv(Duration::from_secs(1).min(wait))? {
                Some(h @ GuestMsg::Hello { .. }) => break h,
                Some(_) => continue,
                None if Instant::now() >= deadline => return Err(format!("timed out waiting for Hello ({wait:?})")),
                None => self.send(&HostMsg::Ping { id: 0 })?,
            }
        };
        let challenge = match &hello {
            GuestMsg::Hello { nonce: Some(n), .. } => n.clone(),
            _ => return Err("the guest agent did not authenticate the channel (no nonce in Hello): rebuild the guest image (`seagent sandbox vm image build --force`) — this channel is reachable by other local processes, so seagent refuses an unauthenticated guest".into()),
        };
        let mine = crate::proto::random_hex(16);
        self.send(&HostMsg::Auth { nonce: mine.clone(), mac: crate::proto::auth_mac(key, "host", &challenge, &mine) })?;
        loop {
            match self.expect(wait, "the guest's Auth")? {
                GuestMsg::Auth { mac } if crate::proto::auth_ok(key, "guest", &mine, &challenge, &mac) => break,
                GuestMsg::Auth { .. } => return Err("the peer on the guest channel failed authentication (wrong key): not the VM seagent started — refusing it".into()),
                GuestMsg::Err { message, .. } if message.contains("authentication failed") => return Err(format!("the guest refused the channel authentication: {message}")),
                // The guest's answers to our pokes ("not authenticated" + Hello) may still be
                // in flight ahead of its Auth.
                _ => continue,
            }
        }
        self.rbuf.lock().unwrap().1.push_front(hello);
        Ok(())
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
            // `Read for &Stream`: the handle is shared, the read state is not.
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
                    let (frames, used) = if self.synced.load(std::sync::atomic::Ordering::SeqCst) {
                        decode::<GuestMsg>(&st.0)?
                    } else {
                        // Firmware noise ahead of the agent's first frame (UART only).
                        loop {
                            let header_ok = st.0.len() < 5 || (u32::from_be_bytes([st.0[0], st.0[1], st.0[2], st.0[3]]) as usize <= crate::proto::MAX_FRAME && st.0[4] == b'{');
                            match decode::<GuestMsg>(&st.0) {
                                Ok((f, u)) if header_ok => {
                                    if !f.is_empty() {
                                        self.synced.store(true, std::sync::atomic::Ordering::SeqCst);
                                    }
                                    break (f, u);
                                }
                                _ if st.0.is_empty() => break (vec![], 0),
                                _ => {
                                    let skip = resync_skip(&st.0);
                                    st.0.drain(..skip);
                                }
                            }
                        }
                    };
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
    fn pair() -> (Channel, Stream) {
        let (a, b) = Stream::pair().unwrap();
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

    /// A fake guest on the other end of a pair (TCP loopback on Windows, a unix pair elsewhere):
    /// sends Hello with `nonce`, answers the host's Auth with `guest_key`'s proof.
    fn auth_peer(guest_key: Option<&'static [u8]>, nonce: Option<&str>) -> (Channel, std::thread::JoinHandle<Option<String>>) {
        let (a, b) = Stream::pair().unwrap();
        let ch = Channel::from_stream(a, Transport::Serial).unwrap();
        let nonce = nonce.map(str::to_string);
        let t = std::thread::spawn(move || {
            let guest = Channel::from_stream(b, Transport::Serial).unwrap();
            let hello = GuestMsg::Hello { version: 1, agent: "fake".into(), kernel: "k".into(), cid: None, transport: "virtio-serial".into(), uid: 1000, nonce: nonce.clone() };
            let mut w = &guest.w;
            w.write_all(&encode(&hello).unwrap()).unwrap();
            // Read the host's Auth with the host-side decoder's twin.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let auth = loop {
                let n = (&guest.r).read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(m) = decode::<HostMsg>(&buf).unwrap().0.into_iter().next() {
                    break m;
                }
            };
            let HostMsg::Auth { nonce: hn, mac } = auth else { return Some("not auth".into()) };
            let answer = match crate::proto::guest_auth_answer(guest_key.unwrap_or(b"none"), nonce.as_deref().unwrap_or(""), &hn, &mac) {
                Ok(a) => a,
                Err(e) => GuestMsg::Err { id: 0, message: e },
            };
            w.write_all(&encode(&answer).unwrap()).unwrap();
            Some(hn)
        });
        (ch, t)
    }

    #[test]
    fn a_keyed_channel_authenticates_both_ways_and_keeps_the_hello() {
        let key: &'static [u8] = b"0123456789abcdef";
        // The real guest: both proofs check, and the Hello is still the first frame read.
        let (ch, t) = auth_peer(Some(key), Some("g-nonce"));
        ch.authenticate(key, Duration::from_secs(5)).unwrap();
        assert!(matches!(ch.expect(Duration::from_secs(1), "hello").unwrap(), GuestMsg::Hello { nonce: Some(_), .. }));
        assert!(t.join().unwrap().is_some_and(|n| n.len() == 32), "the host sent a fresh 16-byte nonce");
        // A squatter without the key: its answer (or its refusal of our proof) is rejected.
        let (ch, _t) = auth_peer(Some(b"wrong-key-wrong!"), Some("g-nonce"));
        let e = ch.authenticate(key, Duration::from_secs(5)).unwrap_err();
        assert!(e.contains("refused") || e.contains("failed authentication"), "{e}");
        // An old guest that never offers a challenge is refused on a keyed channel.
        let (ch, _t) = auth_peer(None, None);
        assert!(ch.authenticate(key, Duration::from_secs(5)).unwrap_err().contains("no nonce"));
        // And the guest side refuses a host proof made with another key.
        assert!(crate::proto::guest_auth_answer(key, "c", "n", &crate::proto::auth_mac(b"other", "host", "c", "n")).is_err());
        assert!(matches!(crate::proto::guest_auth_answer(key, "c", "n", &crate::proto::auth_mac(key, "host", "c", "n")), Ok(GuestMsg::Auth { .. })));
    }

    /// UEFI prints terminal escapes on every serial port before the agent owns COM2 (seen on
    /// a real UEFI boot): a UART channel skips that noise up to the first frame; every other
    /// transport stays strict.
    #[test]
    fn a_uart_channel_skips_firmware_noise_before_the_first_frame() {
        let first = GuestMsg::Pong { id: 9 };
        let mut bytes = b"\x1b[=3h\x1b[2J\x1b[01;01HBdsDxe: loading Boot0001 {x}\r\n".to_vec();
        bytes.extend(encode(&first).unwrap());
        bytes.extend(encode(&GuestMsg::Pong { id: 10 }).unwrap());
        let (a, mut b) = Stream::pair().unwrap();
        let ch = Channel::from_stream(a, Transport::Uart).unwrap();
        b.write_all(&bytes).unwrap();
        assert_eq!(ch.expect(Duration::from_secs(2), "pong").unwrap(), first);
        assert_eq!(ch.expect(Duration::from_secs(2), "pong").unwrap(), GuestMsg::Pong { id: 10 });
        // Once in sync, the UART is strict too.
        b.write_all(b"\x1b[2Jgarbage-after-sync").unwrap();
        assert!(ch.recv(Duration::from_millis(300)).is_err());
        let (a, mut b) = Stream::pair().unwrap();
        let strict = Channel::from_stream(a, Transport::Serial).unwrap();
        b.write_all(&bytes).unwrap();
        assert!(strict.recv(Duration::from_millis(300)).is_err(), "virtio-serial / unix / vsock keep their exact framing");
        assert_eq!(resync_skip(b"\x1b"), 1);
    }

    #[test]
    fn vsock_handshake_rejects_garbage() {
        let (a, mut b) = Stream::pair().unwrap();
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

    #[test]
    fn a_proxied_vsock_and_a_uart_need_no_preamble_and_tell_the_guest_what_to_open() {
        assert_eq!(Transport::VsockProxy { port: 5000 }.name(), "vsock", "vfkit/crosvm guests listen on AF_VSOCK");
        assert_eq!(Transport::Uart.name(), "uart");
        let (a, mut b) = Stream::pair().unwrap();
        let ch = Channel::from_stream(a, Transport::VsockProxy { port: 5000 }).unwrap();
        b.write_all(&encode(&GuestMsg::Pong { id: 0 }).unwrap()).unwrap();
        assert!(matches!(ch.expect(Duration::from_secs(2), "pong").unwrap(), GuestMsg::Pong { .. }), "the first bytes are frames, not a CONNECT reply");
    }

    #[test]
    fn endpoints_are_unix_sockets_on_unix_and_loopback_records_elsewhere() {
        let p = PathBuf::from("/run/vm/x/chan.sock");
        assert_eq!(Endpoint::Unix(p.clone()).qemu_chardev("seagent0"), format!("socket,id=seagent0,path={},server=on,wait=off", p.display()), "Linux keeps its exact chardev");
        assert_eq!(Endpoint::Unix(p.clone()).qemu_monitor(), format!("unix:{},server=on,wait=off", p.display()));
        let tcp = Endpoint::Tcp("127.0.0.1:4555".parse().unwrap());
        assert_eq!(tcp.qemu_chardev("c"), "socket,id=c,host=127.0.0.1,port=4555,server=on,wait=off,nodelay=on", "Windows QEMU: loopback only, no Nagle delay");
        assert_eq!(tcp.qemu_monitor(), "tcp:127.0.0.1:4555,server=on,wait=off");
        if cfg!(unix) {
            assert_eq!(Endpoint::locate(&p).unwrap(), Endpoint::Unix(p));
        }
        // The record format round-trips (what Windows writes into `chan.sock`).
        let t = crate::hostcaps::tests_support::seagent_tmp("endpoint");
        let rec = t.join("chan.sock");
        tcp.record(&rec).unwrap();
        assert_eq!(std::fs::read_to_string(&rec).unwrap(), "tcp:127.0.0.1:4555\n");
    }
}
