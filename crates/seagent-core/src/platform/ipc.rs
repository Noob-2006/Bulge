//! Local, owner-only stream transport for the daemon control socket and the brokers.
//!
//! An endpoint is named by a filesystem path (the kernel's `Paths::socket()` and friends), so
//! callers do not change shape between systems:
//!
//! * **Unix** — the path *is* a unix socket, used exactly as `seagent-kernel`'s daemon does:
//!   a live socket at the path is `AddrInUse`, a stale one is removed, the new socket is
//!   `chmod 0600` right after `bind`, and the daemon polls a non-blocking `accept` every 50 ms.
//!   Making the directory `0700` stays the caller's job ([`super::fs_private::create_dir_private`]),
//!   as it is today.
//! * **Windows** — the path maps to a named pipe `\\.\pipe\seagent-<user>-<file>-<hash>`
//!   ([`pipe_name`]; the hash of the full path keeps two profiles apart). Every instance carries
//!   a protected DACL for the current user only and rejects remote clients; the first instance
//!   is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a pipe someone else already owns is
//!   `AddrInUse` instead of a shared endpoint. One instance per connection: as soon as a client
//!   connects, the next instance is created, so a connecting client never finds no instance.
//!   Non-blocking `accept` uses `PIPE_NOWAIT` on the listening instance; read timeouts poll
//!   `PeekNamedPipe` (pipes have no per-handle timeout). Clients open the pipe with
//!   `SECURITY_IDENTIFICATION`, so the server can identify but not impersonate them.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// FNV-1a, 64 bit: a stable, dependency-free name hash (not a security boundary; the DACL is).
fn fnv1a(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
}

fn clean(s: &str) -> String {
    let c: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c.to_ascii_lowercase() } else { '_' }).take(40).collect();
    if c.is_empty() {
        "x".into()
    } else {
        c
    }
}

/// The Windows pipe name for endpoint `path` (pure; any host).
pub fn pipe_name_for(path: &Path, user: &str) -> String {
    // Split on both separators: the name must not depend on the host that computes it.
    let full = path.to_string_lossy();
    let last = full.rsplit(['/', '\\']).next().unwrap_or("");
    let file = last.rsplit_once('.').map_or(last, |(stem, _)| if stem.is_empty() { last } else { stem });
    format!("\\\\.\\pipe\\seagent-{}-{}-{:016x}", clean(user), clean(file), fnv1a(&path.to_string_lossy()))
}

/// The Windows pipe name of endpoint `path` for the current user.
pub fn pipe_name(path: &Path) -> String {
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".into());
    pipe_name_for(path, &user)
}

/// What [`IpcListener::bind`] / [`IpcStream::connect`] actually use: the socket path on Unix,
/// the pipe name on Windows (for messages and `seagent doctor`).
pub fn endpoint_display(path: &Path) -> String {
    if cfg!(windows) {
        pipe_name(path)
    } else {
        path.display().to_string()
    }
}

// ───────────────────────── Unix ─────────────────────────

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    pub struct Listener {
        pub inner: UnixListener,
    }

    impl Listener {
        pub fn bind(path: &Path) -> io::Result<Listener> {
            use std::os::unix::fs::PermissionsExt;
            if path.exists() {
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{} is in use by a running process", path.display())));
                }
                std::fs::remove_file(path)?; // stale
            }
            let inner = UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Listener { inner })
        }
        pub fn accept(&self) -> io::Result<Stream> {
            self.inner.accept().map(|(s, _)| Stream { inner: s })
        }
        pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
            self.inner.set_nonblocking(on)
        }
    }

    pub struct Stream {
        pub inner: UnixStream,
    }

    impl Stream {
        pub fn connect(path: &Path) -> io::Result<Stream> {
            UnixStream::connect(path).map(|s| Stream { inner: s })
        }
        pub fn try_clone(&self) -> io::Result<Stream> {
            self.inner.try_clone().map(|s| Stream { inner: s })
        }
        pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
            self.inner.set_nonblocking(on)
        }
        pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
            self.inner.set_read_timeout(t)
        }
        pub fn set_write_timeout(&self, t: Option<Duration>) -> io::Result<()> {
            self.inner.set_write_timeout(t)
        }
        pub fn shutdown(&self) -> io::Result<()> {
            self.inner.shutdown(std::net::Shutdown::Both)
        }
        pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            (&self.inner).read(buf)
        }
        pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
            (&self.inner).write(buf)
        }
        pub fn flush(&self) -> io::Result<()> {
            (&self.inner).flush()
        }
    }
}

// ───────────────────────── Windows ─────────────────────────

#[cfg(windows)]
mod imp {
    use super::super::fs_private::win::{wide, OwnerSd};
    use super::*;
    use std::fs::File;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION};
    use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe, SetNamedPipeHandleState, WaitNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT};

    const BUF: u32 = 64 * 1024;

    fn h(f: &File) -> HANDLE {
        f.as_raw_handle() as HANDLE
    }

    fn os_err(e: &io::Error) -> u32 {
        e.raw_os_error().unwrap_or(0) as u32
    }

    pub struct Listener {
        name: String,
        wide: Vec<u16>,
        sd: OwnerSd,
        /// The instance clients connect to next.
        pending: Mutex<Option<File>>,
        nonblocking: AtomicBool,
    }

    impl Listener {
        pub fn bind(path: &Path) -> io::Result<Listener> {
            let name = pipe_name(path);
            match std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(SECURITY_IDENTIFICATION).open(&name) {
                Ok(_) => return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{name} is in use by a running process"))),
                Err(e) if os_err(&e) == ERROR_PIPE_BUSY => return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{name} is in use by a running process"))),
                Err(_) => {}
            }
            let l = Listener { wide: wide(&name), name, sd: OwnerSd::new(false, "GA")?, pending: Mutex::new(None), nonblocking: AtomicBool::new(false) };
            let first = l.instance(true)?;
            *l.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(first);
            Ok(l)
        }

        fn instance(&self, first: bool) -> io::Result<File> {
            let sa = self.sd.attributes();
            let open = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
            // SAFETY: valid NUL-terminated name and SECURITY_ATTRIBUTES (kept alive by `self`).
            let hp = unsafe { CreateNamedPipeW(self.wide.as_ptr(), open, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, BUF, BUF, 0, &sa) };
            if hp == INVALID_HANDLE_VALUE {
                let e = io::Error::last_os_error();
                if first && os_err(&e) == ERROR_ACCESS_DENIED {
                    return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{} is owned by another process", self.name)));
                }
                return Err(e);
            }
            // SAFETY: a fresh handle we own.
            Ok(unsafe { File::from_raw_handle(hp as RawHandle) })
        }

        fn set_mode(f: &File, mode: u32) -> io::Result<()> {
            // SAFETY: valid pipe handle; only the mode is changed.
            if unsafe { SetNamedPipeHandleState(h(f), &mode, std::ptr::null(), std::ptr::null()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn connected(&self, inst: File) -> io::Result<Stream> {
            Self::set_mode(&inst, PIPE_READMODE_BYTE | PIPE_WAIT)?;
            let mut slot = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if slot.is_none() {
                *slot = Some(self.instance(false)?);
            }
            Ok(Stream::new(inst))
        }

        pub fn accept(&self) -> io::Result<Stream> {
            let inst = self.pending.lock().unwrap_or_else(|e| e.into_inner()).take();
            let inst = match inst {
                Some(f) => f,
                None => self.instance(false)?,
            };
            if self.nonblocking.load(Ordering::SeqCst) {
                Self::set_mode(&inst, PIPE_READMODE_BYTE | PIPE_NOWAIT)?;
                // SAFETY: valid pipe handle, synchronous call.
                let ok = unsafe { ConnectNamedPipe(h(&inst), std::ptr::null_mut()) };
                let e = io::Error::last_os_error();
                let code = if ok != 0 { 0 } else { os_err(&e) };
                return match code {
                    ERROR_PIPE_CONNECTED => self.connected(inst),
                    // 0: freshly listening; nobody there yet.
                    0 | ERROR_PIPE_LISTENING => {
                        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(inst);
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                    ERROR_NO_DATA => {
                        // A client came and went: recycle the instance.
                        // SAFETY: valid pipe handle.
                        unsafe { DisconnectNamedPipe(h(&inst)) };
                        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(inst);
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                    _ => Err(e),
                };
            }
            Self::set_mode(&inst, PIPE_READMODE_BYTE | PIPE_WAIT)?;
            // SAFETY: valid pipe handle; blocks until a client connects.
            if unsafe { ConnectNamedPipe(h(&inst), std::ptr::null_mut()) } == 0 {
                let e = io::Error::last_os_error();
                if os_err(&e) != ERROR_PIPE_CONNECTED {
                    return Err(e);
                }
            }
            self.connected(inst)
        }

        pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
            self.nonblocking.store(on, Ordering::SeqCst);
            Ok(())
        }
    }

    pub struct Stream {
        file: File,
        /// Read timeout in nanoseconds; 0 = none.
        timeout: AtomicU64,
        nonblocking: AtomicBool,
    }

    impl Stream {
        fn new(file: File) -> Stream {
            Stream { file, timeout: AtomicU64::new(0), nonblocking: AtomicBool::new(false) }
        }

        pub fn connect(path: &Path) -> io::Result<Stream> {
            let name = pipe_name(path);
            let w = wide(&name);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(SECURITY_IDENTIFICATION).open(&name) {
                    Ok(f) => return Ok(Stream::new(f)),
                    Err(e) if os_err(&e) == ERROR_PIPE_BUSY && Instant::now() < deadline => {
                        // SAFETY: valid NUL-terminated name.
                        unsafe { WaitNamedPipeW(w.as_ptr(), 250) };
                    }
                    Err(e) => return Err(io::Error::new(e.kind(), format!("{name}: {e}"))),
                }
            }
        }

        pub fn try_clone(&self) -> io::Result<Stream> {
            let s = Stream::new(self.file.try_clone()?);
            s.timeout.store(self.timeout.load(Ordering::SeqCst), Ordering::SeqCst);
            s.nonblocking.store(self.nonblocking.load(Ordering::SeqCst), Ordering::SeqCst);
            Ok(s)
        }

        /// Reads only: a write to a full pipe still blocks.
        pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
            self.nonblocking.store(on, Ordering::SeqCst);
            Ok(())
        }

        pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
            if t == Some(Duration::ZERO) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot set a 0 duration timeout"));
            }
            self.timeout.store(t.map(|d| d.as_nanos().min(u64::MAX as u128) as u64).unwrap_or(0), Ordering::SeqCst);
            Ok(())
        }

        /// Accepted for API parity; pipe writes have no timeout.
        pub fn set_write_timeout(&self, _t: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        pub fn shutdown(&self) -> io::Result<()> {
            Ok(())
        }

        /// Wait until a read will not block (data, or the other end closed).
        fn wait_readable(&self) -> io::Result<()> {
            let nb = self.nonblocking.load(Ordering::SeqCst);
            let t = self.timeout.load(Ordering::SeqCst);
            if !nb && t == 0 {
                return Ok(());
            }
            let deadline = Instant::now() + Duration::from_nanos(t);
            loop {
                let mut avail = 0u32;
                // SAFETY: valid pipe handle; only the available byte count is requested.
                if unsafe { PeekNamedPipe(h(&self.file), std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) } == 0 {
                    let e = io::Error::last_os_error();
                    return if os_err(&e) == ERROR_BROKEN_PIPE { Ok(()) } else { Err(e) };
                }
                if avail > 0 {
                    return Ok(());
                }
                if nb {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "pipe read timed out"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.wait_readable()?;
            (&self.file).read(buf)
        }
        pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
            (&self.file).write(buf)
        }
        pub fn flush(&self) -> io::Result<()> {
            (&self.file).flush()
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;
    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no local IPC on this target"))
    }
    pub struct Listener;
    impl Listener {
        pub fn bind(_: &Path) -> io::Result<Listener> {
            unsupported()
        }
        pub fn accept(&self) -> io::Result<Stream> {
            unsupported()
        }
        pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
            unsupported()
        }
    }
    pub struct Stream;
    impl Stream {
        pub fn connect(_: &Path) -> io::Result<Stream> {
            unsupported()
        }
        pub fn try_clone(&self) -> io::Result<Stream> {
            unsupported()
        }
        pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
            unsupported()
        }
        pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            unsupported()
        }
        pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            unsupported()
        }
        pub fn shutdown(&self) -> io::Result<()> {
            unsupported()
        }
        pub fn read(&self, _: &mut [u8]) -> io::Result<usize> {
            unsupported()
        }
        pub fn write(&self, _: &[u8]) -> io::Result<usize> {
            unsupported()
        }
        pub fn flush(&self) -> io::Result<()> {
            unsupported()
        }
    }
}

// ───────────────────────── portable surface ─────────────────────────

/// A bound endpoint. See the module docs for what `bind` does on each OS.
pub struct IpcListener {
    inner: imp::Listener,
    path: PathBuf,
}

impl IpcListener {
    /// Bind endpoint `path`: `AddrInUse` when a live server holds it (a stale Unix socket is
    /// removed). Unix: the socket is `0600`. Windows: owner-only pipe instances.
    pub fn bind(path: &Path) -> io::Result<IpcListener> {
        Ok(IpcListener { inner: imp::Listener::bind(path)?, path: path.to_path_buf() })
    }

    /// The next client. `WouldBlock` when non-blocking and nobody is waiting.
    pub fn accept(&self) -> io::Result<IpcStream> {
        self.inner.accept().map(|inner| IpcStream { inner })
    }

    /// Non-blocking accept, for a loop that also watches a stop flag (the daemon polls every 50 ms).
    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.inner.set_nonblocking(on)
    }

    /// The path this endpoint was bound to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the endpoint's filesystem trace (Unix: the socket file; Windows: nothing — a
    /// pipe disappears with its last handle). Call it on orderly shutdown, as the daemon does.
    pub fn cleanup(&self) {
        if cfg!(unix) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// The Unix listener (for `poll` / fd passing).
    #[cfg(unix)]
    pub fn as_unix(&self) -> &std::os::unix::net::UnixListener {
        &self.inner.inner
    }
}

/// One connection, either side.
pub struct IpcStream {
    inner: imp::Stream,
}

impl IpcStream {
    /// Connect to endpoint `path` (Windows: waits up to 5 s while all pipe instances are busy).
    pub fn connect(path: &Path) -> io::Result<IpcStream> {
        imp::Stream::connect(path).map(|inner| IpcStream { inner })
    }
    /// A second handle to the same connection (one thread reads, another writes).
    pub fn try_clone(&self) -> io::Result<IpcStream> {
        self.inner.try_clone().map(|inner| IpcStream { inner })
    }
    /// Windows: reads only (writes to a full pipe still block).
    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.inner.set_nonblocking(on)
    }
    /// A read that waits longer fails with `WouldBlock` (Unix) or `TimedOut` (Windows).
    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(t)
    }
    /// Windows: accepted and ignored (pipes have no write timeout).
    pub fn set_write_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(t)
    }
    /// Close both directions (Unix `shutdown(Both)`; Windows: no-op, drop closes).
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown()
    }
    /// The Unix stream (for `poll`, peer credentials, fd passing).
    #[cfg(unix)]
    pub fn as_unix(&self) -> &std::os::unix::net::UnixStream {
        &self.inner.inner
    }
}

impl Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Read for &IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl Write for &IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for IpcStream {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.inner.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::{BufRead, BufReader};

    #[test]
    fn pipe_names_are_stable_clean_and_distinct() {
        let a = pipe_name_for(Path::new("C:\\Users\\u\\AppData\\Local\\seagent\\run\\seagentd.sock"), "Jo Doe");
        assert!(a.starts_with("\\\\.\\pipe\\seagent-jo_doe-seagentd-"), "{a}");
        assert_eq!(a, pipe_name_for(Path::new("C:\\Users\\u\\AppData\\Local\\seagent\\run\\seagentd.sock"), "Jo Doe"));
        assert_ne!(a, pipe_name_for(Path::new("C:\\p\\other\\run\\seagentd.sock"), "Jo Doe"), "two profiles, two pipes");
        assert!(pipe_name_for(Path::new(""), "").contains("seagent-x-x-"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_endpoint_round_trip_like_the_daemon() {
        use std::os::unix::fs::PermissionsExt;
        let t = crate::tmp::TempDir::new("seagent-ipc");
        let dir = t.path().join("run");
        super::super::fs_private::create_dir_private(&dir).unwrap();
        let sock = dir.join("d.sock");
        let l = IpcListener::bind(&sock).unwrap();
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
        l.set_nonblocking(true).unwrap();
        assert_eq!(l.accept().err().map(|e| e.kind()), Some(io::ErrorKind::WouldBlock));
        // a live endpoint cannot be bound twice
        assert_eq!(IpcListener::bind(&sock).err().map(|e| e.kind()), Some(io::ErrorKind::AddrInUse));
        let server = std::thread::spawn(move || {
            loop {
                let conn = match l.accept() {
                    Ok(c) => c,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                conn.set_nonblocking(false).unwrap();
                let mut w = conn.try_clone().unwrap();
                let mut line = String::new();
                BufReader::new(conn).read_line(&mut line).unwrap();
                if line.is_empty() {
                    continue; // the liveness probe of the second bind: connected and left
                }
                w.write_all(format!("echo {line}").as_bytes()).unwrap();
                break;
            }
            l.cleanup();
        });
        let mut c = IpcStream::connect(&sock).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(b"hi\n").unwrap();
        let mut reply = String::new();
        BufReader::new(&c).read_line(&mut reply).unwrap();
        assert_eq!(reply, "echo hi\n");
        server.join().unwrap();
        assert!(!sock.exists(), "cleanup removes the socket");
        // stale socket files are replaced
        let l =std::os::unix::net::UnixListener::bind(&sock).unwrap();
        drop(l);
        assert!(IpcListener::bind(&sock).is_ok());
        assert_eq!(endpoint_display(&sock), sock.display().to_string());
    }
}
