//! TCP listeners for [`crate::httpd::Server`], with a real dual-stack option.
//!
//! [`tcp`] binds what it is given with std — except `[::]:<port>`, which becomes **one
//! dual-stack socket** (`IPV6_V6ONLY` cleared, then read back to confirm, so IPv4 clients
//! arrive as `::ffff:a.b.c.d` on the same port) on every platform, Windows included (std
//! leaves the platform default: dual-stack on Linux / macOS, IPv6-only on Windows). Where the
//! system will not clear the option (OpenBSD, `net.ipv6.bindv6only = 1` jails) it falls back
//! to two listeners, `[::]` (IPv6-only) and `0.0.0.0`; with no IPv6 at all, to `0.0.0.0`
//! alone. The socket is made by hand (`libc::socket` / `WSASocketW`) because std cannot set
//! options before `bind`; like std's it is close-on-exec / not inheritable, and on unix has
//! `SO_REUSEADDR`. Peers are canonicalised by the server ([`canonical`]) so policy code sees
//! `192.168.1.5`, never `::ffff:192.168.1.5`.

use std::io;
use std::net::{SocketAddr, TcpListener};

/// `::ffff:a.b.c.d` → `a.b.c.d`; everything else unchanged.
pub fn canonical(a: SocketAddr) -> SocketAddr {
    match a {
        // Only the mapped form changes: a link-local peer keeps its scope id.
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => a,
        },
        SocketAddr::V4(_) => a,
    }
}

/// Why a dual-stack socket could not be made: `Unsupported` means "fall back", anything else
/// (the port is taken, permission) is the caller's error.
enum DualErr {
    Unsupported,
    Io(io::Error),
}

/// The port of `[::]:<port>` / `[::]`, `None` for any other address.
fn wildcard_v6_port(addr: &str) -> Option<u16> {
    match addr.trim().parse::<SocketAddr>() {
        Ok(SocketAddr::V6(a)) if a.ip().is_unspecified() && a.scope_id() == 0 => Some(a.port()),
        _ => None,
    }
}

/// Listeners for `addr` (see the module docs). The first one's address is the server's.
pub fn tcp(addr: &str) -> io::Result<Vec<TcpListener>> {
    let Some(port) = wildcard_v6_port(addr) else { return Ok(vec![TcpListener::bind(addr)?]) };
    match v6_socket(port, false) {
        Ok(l) => Ok(vec![l]),
        Err(DualErr::Io(e)) => Err(e),
        Err(DualErr::Unsupported) => match v6_socket(port, true) {
            Ok(v6) => {
                let port = v6.local_addr()?.port();
                let v4 = TcpListener::bind(("0.0.0.0", port))?;
                Ok(vec![v6, v4])
            }
            Err(DualErr::Io(e)) => Err(e),
            Err(DualErr::Unsupported) => Ok(vec![TcpListener::bind(("0.0.0.0", port))?]),
        },
    }
}

/// Is this listener dual-stack (one IPv6 socket that also takes IPv4)?
pub fn is_dual_stack(l: &TcpListener) -> bool {
    matches!(l.local_addr(), Ok(SocketAddr::V6(_))) && v6only(l) == Some(false)
}

#[cfg(unix)]
fn v6only(l: &TcpListener) -> Option<bool> {
    use std::os::fd::AsRawFd;
    let mut v: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: reads one int option into `v`.
    let rc = unsafe { libc::getsockopt(l.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &mut v as *mut _ as *mut libc::c_void, &mut len) };
    (rc == 0).then_some(v != 0)
}

#[cfg(windows)]
fn v6only(l: &TcpListener) -> Option<bool> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock as ws;
    let mut v: i32 = -1;
    let mut len = 4i32;
    // SAFETY: reads one DWORD option into `v`.
    let rc = unsafe { ws::getsockopt(l.as_raw_socket() as ws::SOCKET, ws::IPPROTO_IPV6, ws::IPV6_V6ONLY, &mut v as *mut i32 as *mut u8, &mut len) };
    (rc == 0).then_some(v != 0)
}

#[cfg(not(any(unix, windows)))]
fn v6only(_l: &TcpListener) -> Option<bool> {
    None
}

#[cfg(unix)]
fn v6_socket(port: u16, only: bool) -> Result<TcpListener, DualErr> {
    use std::os::fd::FromRawFd;
    let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: BSD socket calls on a descriptor we own; it goes to TcpListener (which closes it)
    // or is closed here on every error path.
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(DualErr::Unsupported);
        }
        let fail = |e: DualErr| {
            libc::close(fd);
            Err(e)
        };
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        let one: libc::c_int = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const _ as *const libc::c_void, sz);
        let want: libc::c_int = only.into();
        let mut got: libc::c_int = -1;
        let mut len = sz;
        if libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &want as *const _ as *const libc::c_void, sz) != 0 || libc::getsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &mut got as *mut _ as *mut libc::c_void, &mut len) != 0 || got != want {
            return fail(DualErr::Unsupported);
        }
        let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sa.sin6_port = port.to_be();
        sa.sin6_addr = libc::in6_addr { s6_addr: std::net::Ipv6Addr::UNSPECIFIED.octets() };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        }
        if libc::bind(fd, &sa as *const libc::sockaddr_in6 as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t) != 0 || libc::listen(fd, 128) != 0 {
            let e = io::Error::last_os_error();
            return fail(DualErr::Io(e));
        }
        Ok(TcpListener::from_raw_fd(fd))
    }
}

#[cfg(windows)]
fn v6_socket(port: u16, only: bool) -> Result<TcpListener, DualErr> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock as ws;
    // std initialises Winsock lazily; make sure it has happened before calling it directly.
    drop(std::net::UdpSocket::bind("127.0.0.1:0"));
    // SAFETY: Winsock calls on a socket we own; it goes to TcpListener or is closed on error.
    unsafe {
        let s = ws::WSASocketW(ws::AF_INET6 as i32, ws::SOCK_STREAM as i32, ws::IPPROTO_TCP, std::ptr::null(), 0, ws::WSA_FLAG_OVERLAPPED | ws::WSA_FLAG_NO_HANDLE_INHERIT);
        if s == ws::INVALID_SOCKET {
            return Err(DualErr::Unsupported);
        }
        let fail = |e: DualErr| {
            ws::closesocket(s);
            Err(e)
        };
        let want: i32 = only.into();
        let mut got: i32 = -1;
        let mut len = 4i32;
        if ws::setsockopt(s, ws::IPPROTO_IPV6, ws::IPV6_V6ONLY, &want as *const i32 as *const u8, 4) != 0 || ws::getsockopt(s, ws::IPPROTO_IPV6, ws::IPV6_V6ONLY, &mut got as *mut i32 as *mut u8, &mut len) != 0 || got != want {
            return fail(DualErr::Unsupported);
        }
        let mut sa: ws::SOCKADDR_IN6 = std::mem::zeroed();
        sa.sin6_family = ws::AF_INET6;
        sa.sin6_port = port.to_be();
        if ws::bind(s, &sa as *const ws::SOCKADDR_IN6 as *const ws::SOCKADDR, std::mem::size_of::<ws::SOCKADDR_IN6>() as i32) != 0 || ws::listen(s, 128) != 0 {
            let e = io::Error::last_os_error();
            return fail(DualErr::Io(e));
        }
        Ok(TcpListener::from_raw_socket(s as u64))
    }
}

#[cfg(not(any(unix, windows)))]
fn v6_socket(port: u16, only: bool) -> Result<TcpListener, DualErr> {
    let _ = only;
    TcpListener::bind(("::", port)).map_err(DualErr::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    #[test]
    fn only_the_v6_wildcard_is_special() {
        assert_eq!(wildcard_v6_port("[::]:8640"), Some(8640));
        assert_eq!(wildcard_v6_port("[::]:0"), Some(0));
        for other in ["0.0.0.0:8640", "127.0.0.1:8640", "[::1]:8640", "[fd00::1]:8640", "localhost:8640"] {
            assert_eq!(wildcard_v6_port(other), None, "{other}");
        }
        assert_eq!(canonical("[::ffff:192.168.1.5]:9".parse().unwrap()), "192.168.1.5:9".parse::<SocketAddr>().unwrap());
        assert_eq!(canonical("[fe80::1%2]:9".parse().unwrap()), "[fe80::1%2]:9".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn loopback_keeps_the_std_listener() {
        let l = tcp("127.0.0.1:0").unwrap();
        assert_eq!(l.len(), 1);
        assert!(l[0].local_addr().unwrap().ip().is_loopback() && l[0].local_addr().unwrap().is_ipv4());
    }

    /// `[::]:0` takes IPv4 and IPv6 clients on one port — one dual-stack socket, or the
    /// two-listener fallback. Skips when this machine has no IPv6 loopback.
    #[test]
    fn the_v6_wildcard_accepts_both_families() {
        let ls = tcp("[::]:0").unwrap();
        let port = ls[0].local_addr().unwrap().port();
        assert!(ls.iter().all(|l| l.local_addr().unwrap().port() == port));
        assert!(TcpStream::connect(("127.0.0.1", port)).is_ok(), "IPv4 reaches the [::] listener");
        if ls.len() == 1 && ls[0].local_addr().unwrap().is_ipv4() {
            eprintln!("skipping the IPv6 half: no IPv6 here");
            return;
        }
        assert!(TcpStream::connect(("::1", port)).is_ok());
        eprintln!("dual-stack: {}", ls.len() == 1 && is_dual_stack(&ls[0]));
    }
}
