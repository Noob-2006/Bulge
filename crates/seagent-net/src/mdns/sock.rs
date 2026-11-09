//! The UDP sockets mDNS needs and the options std does not expose.
//!
//! - [`shared`]: `0.0.0.0:5353` / `[::]:5353` opened with `SO_REUSEADDR` (+ `SO_REUSEPORT` on
//!   unix) *before* `bind`, so it shares the port with Avahi / systemd-resolved,
//!   mDNSResponder (macOS / iOS) or the Windows DNS client. std's `UdpSocket::bind` cannot set
//!   options before binding, so the socket is made with `libc::socket` / WinSock `socket` and
//!   handed to std (`from_raw_fd` / `from_raw_socket`). The IPv6 one is `IPV6_V6ONLY`.
//! - [`set_if_v4`] / [`set_if_v6`]: `IP_MULTICAST_IF` / `IPV6_MULTICAST_IF`, the interface a
//!   multicast send leaves by; [`prepare`]: loopback on, TTL / hop limit 255 (RFC 6762 §11).

use std::io;
use std::net::{Ipv4Addr, UdpSocket};

use super::PORT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fam {
    V4,
    V6,
}

#[cfg(unix)]
fn setopt<T>(s: &UdpSocket, level: libc::c_int, name: libc::c_int, v: &T) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `v` points at a live `T` of the size we pass.
    let rc = unsafe { libc::setsockopt(s.as_raw_fd(), level, name, v as *const T as *const libc::c_void, std::mem::size_of::<T>() as libc::socklen_t) };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(windows)]
fn setopt<T>(s: &UdpSocket, level: i32, name: i32, v: &T) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock as ws;
    // SAFETY: `v` points at a live `T` of the size we pass.
    let rc = unsafe { ws::setsockopt(s.as_raw_socket() as ws::SOCKET, level, name, v as *const T as *const u8, std::mem::size_of::<T>() as i32) };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// The interface (by one of its IPv4 addresses) that IPv4 multicast sends leave by.
pub fn set_if_v4(s: &UdpSocket, addr: Ipv4Addr) -> io::Result<()> {
    // `struct in_addr`, network byte order: the same 4 bytes on every platform.
    let a = u32::from_ne_bytes(addr.octets());
    #[cfg(unix)]
    return setopt(s, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &libc::in_addr { s_addr: a });
    #[cfg(windows)]
    return setopt(s, windows_sys::Win32::Networking::WinSock::IPPROTO_IP, windows_sys::Win32::Networking::WinSock::IP_MULTICAST_IF, &a);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (s, a);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// The interface (by index) that IPv6 multicast sends leave by.
pub fn set_if_v6(s: &UdpSocket, index: u32) -> io::Result<()> {
    #[cfg(unix)]
    return setopt(s, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &(index as libc::c_uint));
    #[cfg(windows)]
    return setopt(s, windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6, windows_sys::Win32::Networking::WinSock::IPV6_MULTICAST_IF, &index);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (s, index);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

fn set_hops_v6(s: &UdpSocket, hops: i32) -> io::Result<()> {
    #[cfg(unix)]
    return setopt(s, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &(hops as libc::c_int));
    #[cfg(windows)]
    return setopt(s, windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6, windows_sys::Win32::Networking::WinSock::IPV6_MULTICAST_HOPS, &hops);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (s, hops);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Multicast loopback on (so a browser on this machine hears us) and TTL / hop limit 255.
pub fn prepare(s: &UdpSocket, fam: Fam) -> io::Result<()> {
    match fam {
        Fam::V4 => {
            s.set_multicast_loop_v4(true)?;
            s.set_multicast_ttl_v4(255)
        }
        Fam::V6 => {
            s.set_multicast_loop_v6(true)?;
            set_hops_v6(s, 255)
        }
    }
}

/// An ephemeral-port socket of `fam` (the legacy-unicast querier, or the announcer when 5353
/// cannot be shared).
pub fn ephemeral(fam: Fam) -> io::Result<UdpSocket> {
    let s = match fam {
        Fam::V4 => UdpSocket::bind("0.0.0.0:0")?,
        Fam::V6 => UdpSocket::bind("[::]:0")?,
    };
    prepare(&s, fam)?;
    Ok(s)
}

/// Port 5353 of `fam`, shared with the system's responder.
#[cfg(unix)]
pub fn shared(fam: Fam) -> io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    let af = if fam == Fam::V4 { libc::AF_INET } else { libc::AF_INET6 };
    // SAFETY: plain BSD socket calls on a descriptor we own; it is handed to UdpSocket (which
    // closes it) or closed here on error.
    let s = unsafe {
        let fd = libc::socket(af, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let opt = |level, name| libc::setsockopt(fd, level, name, &one as *const _ as *const libc::c_void, sz);
        opt(libc::SOL_SOCKET, libc::SO_REUSEADDR);
        opt(libc::SOL_SOCKET, libc::SO_REUSEPORT);
        let rc = if fam == Fam::V4 {
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = PORT.to_be();
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            libc::bind(fd, &sa as *const libc::sockaddr_in as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        } else {
            opt(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY);
            let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = PORT.to_be();
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            libc::bind(fd, &sa as *const libc::sockaddr_in6 as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        UdpSocket::from_raw_fd(fd)
    };
    prepare(&s, fam)?;
    Ok(s)
}

/// Port 5353 of `fam`, shared with the system's responder.
#[cfg(windows)]
pub fn shared(fam: Fam) -> io::Result<UdpSocket> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock as ws;
    // std initialises Winsock lazily; make sure it has happened before calling it directly.
    drop(UdpSocket::bind("127.0.0.1:0"));
    let af = if fam == Fam::V4 { ws::AF_INET } else { ws::AF_INET6 };
    // SAFETY: Winsock calls on a socket we own; it is handed to UdpSocket or closed on error.
    let s = unsafe {
        let s = ws::socket(af as i32, ws::SOCK_DGRAM, ws::IPPROTO_UDP);
        if s == ws::INVALID_SOCKET {
            return Err(io::Error::last_os_error());
        }
        let one: i32 = 1;
        ws::setsockopt(s, ws::SOL_SOCKET, ws::SO_REUSEADDR, &one as *const i32 as *const u8, 4);
        let rc = if fam == Fam::V4 {
            let mut sa: ws::SOCKADDR_IN = std::mem::zeroed();
            sa.sin_family = ws::AF_INET;
            sa.sin_port = PORT.to_be();
            ws::bind(s, &sa as *const ws::SOCKADDR_IN as *const ws::SOCKADDR, std::mem::size_of::<ws::SOCKADDR_IN>() as i32)
        } else {
            ws::setsockopt(s, ws::IPPROTO_IPV6, ws::IPV6_V6ONLY, &one as *const i32 as *const u8, 4);
            let mut sa: ws::SOCKADDR_IN6 = std::mem::zeroed();
            sa.sin6_family = ws::AF_INET6;
            sa.sin6_port = PORT.to_be();
            ws::bind(s, &sa as *const ws::SOCKADDR_IN6 as *const ws::SOCKADDR, std::mem::size_of::<ws::SOCKADDR_IN6>() as i32)
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            ws::closesocket(s);
            return Err(e);
        }
        UdpSocket::from_raw_socket(s as u64)
    };
    prepare(&s, fam)?;
    Ok(s)
}

#[cfg(not(any(unix, windows)))]
pub fn shared(fam: Fam) -> io::Result<UdpSocket> {
    match fam {
        Fam::V4 => UdpSocket::bind(("0.0.0.0", PORT)),
        Fam::V6 => UdpSocket::bind(("::", PORT)),
    }
}
