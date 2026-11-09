//! mDNS / DNS-SD (RFC 6762 / 6763) for LAN mode: advertise `_seagent._tcp.local` and browse
//! for other SE Agent hosts, over IPv4 (`224.0.0.251`) and IPv6 (`ff02::fb`) on every
//! suitable interface. std `UdpSocket` plus a few `setsockopt`s — no mDNS crate.
//!
//! - [`wire`]: message encoding / decoding. [`iface`]: interface enumeration and the pure
//!   selection rules (which interfaces, which addresses, which zone). `sock`: sockets and
//!   the options std lacks (port sharing, `IP(V6)_MULTICAST_IF`, hop limit, `IPV6_V6ONLY`).
//!
//! **Responder** ([`Responder::start`]): `0.0.0.0:5353` and `[::]:5353`, shared with the
//! system's responder (`SO_REUSEADDR`, + `SO_REUSEPORT` on unix), joined to the group of its
//! family on every up, multicast-capable, non-loopback interface. It announces twice on start
//! out of each interface, answers PTR / SRV / TXT / A / AAAA / ANY questions with the
//! addresses of the interface the query arrived on (IPv4: the interface whose subnet holds the
//! querier; IPv6: the scope id of a link-local source, else the matching /64; unknown: all
//! interfaces), multicast on that interface, unicast for a QU question, or straight back to
//! the asker for a legacy query from a port other than 5353 (RFC 6762 §6.7). Every 30 s it
//! re-reads the interfaces (Wi-Fi roaming, DHCP), joins / leaves groups and re-announces on
//! change. Stopping or dropping it sends a goodbye (TTL 0) on every interface.
//!
//! When 5353 cannot be shared at all (held exclusively) the responder runs **limited**: it
//! announces from an ephemeral port every 30 s but cannot answer queries; [`responder_status`]
//! and [`port_shareable`] say so (`lan.status`, `seagent doctor`) instead of failing silently.
//!
//! **Browser** ([`browse`]): a PTR query with the QU bit from an ephemeral port per family and
//! interface (legacy unicast: every responder answers it directly, so browsing works even when
//! 5353 cannot be shared), plus a multicast query from shared 5353 sockets when it can get
//! them. AAAA link-local answers get the zone of the interface they arrived on
//! ([`HostAddr::scope`]); one whose zone cannot be told is dropped.
//!
//! The TXT record carries `v`, `id`, `fp` (fingerprint prefix) and `name` — never a token.

pub mod iface;
mod sock;
pub mod wire;

pub use wire::{asks_for, encode_answer, encode_query, encode_response, parse, parse_txt, txt_bytes, Message, RData, Record, Service, SERVICE, T_A, T_AAAA, T_ANY, T_PTR, T_SRV, T_TXT};

use iface::Iface;
use sock::Fam;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
pub const PORT: u16 = 5353;
/// How often the responder re-reads the interfaces.
pub const RESCAN: Duration = Duration::from_secs(30);

/// This machine's address on the LAN: the source address the system would use for a private
/// destination (no packet is sent). `None` when it is not in a private range.
pub fn lan_ipv4() -> Option<Ipv4Addr> {
    for probe in ["192.168.255.254:9", "10.254.254.254:9", "172.31.255.254:9"] {
        let Ok(s) = UdpSocket::bind("0.0.0.0:0") else { continue };
        if s.connect(probe).is_err() {
            continue;
        }
        if let Ok(SocketAddr::V4(a)) = s.local_addr() {
            let ip = *a.ip();
            let [x, y, ..] = ip.octets();
            if x == 10 || (x == 172 && (16..=31).contains(&y)) || (x == 192 && y == 168) || (x == 169 && y == 254) || (x == 100 && (64..=127).contains(&y)) {
                return Some(ip);
            }
        }
    }
    None
}

/// The addresses to put in an answer: the service's fixed ones, else those of the arrival
/// interface (all interfaces when it is unknown), per the service's `auto_v4` / `auto_v6`.
pub fn answer_addrs(svc: &Service, ifaces: &[Iface], arrival: Option<&Iface>) -> Vec<IpAddr> {
    if !svc.addrs.is_empty() {
        return svc.addrs.clone();
    }
    match arrival {
        Some(i) => iface::advertised([i], svc.auto_v4, svc.auto_v6),
        None => iface::advertised(ifaces, svc.auto_v4, svc.auto_v6),
    }
}

// ── transport ──

/// One family's socket and the groups it joined.
struct Net {
    sock: UdpSocket,
    fam: Fam,
    /// Bound to 5353 (receives queries); otherwise an ephemeral announcer / querier.
    shared: bool,
    /// (interface index, the IPv4 address used to join; `None` for IPv6, joined by index).
    joined: Vec<(u32, Option<Ipv4Addr>)>,
}

impl Net {
    fn open(fam: Fam, shared: bool) -> std::io::Result<Net> {
        let sock = if shared { sock::shared(fam)? } else { sock::ephemeral(fam)? };
        Ok(Net { sock, fam, shared, joined: Vec::new() })
    }

    /// Join the group on each interface of `ifaces` that has an address of our family, and
    /// leave the ones that went away.
    fn sync(&mut self, ifaces: &[Iface]) {
        if !self.shared {
            return;
        }
        let want: Vec<(u32, Option<Ipv4Addr>)> = ifaces
            .iter()
            .filter_map(|i| match self.fam {
                Fam::V4 => i.v4.first().map(|(a, _)| (i.index, Some(*a))),
                Fam::V6 => (!i.v6.is_empty()).then_some((i.index, None)),
            })
            .collect();
        for old in self.joined.iter().filter(|j| !want.contains(j)) {
            let _ = match *old {
                (_, Some(a)) => self.sock.leave_multicast_v4(&GROUP, &a),
                (idx, None) => self.sock.leave_multicast_v6(&GROUP_V6, idx),
            };
        }
        self.joined.retain(|j| want.contains(j));
        let new: Vec<(u32, Option<Ipv4Addr>)> = want.into_iter().filter(|w| !self.joined.contains(w)).collect();
        for w in new {
            let r = match w {
                (_, Some(a)) => self.sock.join_multicast_v4(&GROUP, &a),
                (idx, None) => self.sock.join_multicast_v6(&GROUP_V6, idx),
            };
            // Already a member (another interface with the same address) counts as joined.
            if r.is_ok() || r.is_err_and(|e| e.kind() == std::io::ErrorKind::AddrInUse) {
                self.joined.push(w);
            }
        }
    }

    /// Multicast `pkt` out of `i` (or by the default route when `i` is `None`).
    fn send_group(&self, i: Option<&Iface>, pkt: &[u8]) {
        match self.fam {
            Fam::V4 => {
                if let Some(i) = i {
                    let Some((a, _)) = i.v4.first() else { return };
                    if sock::set_if_v4(&self.sock, *a).is_err() {
                        return;
                    }
                }
                let _ = self.sock.send_to(pkt, SocketAddrV4::new(GROUP, PORT));
            }
            Fam::V6 => {
                let idx = match i {
                    Some(i) if i.v6.is_empty() => return,
                    Some(i) => i.index,
                    None => 0,
                };
                if idx != 0 && sock::set_if_v6(&self.sock, idx).is_err() {
                    return;
                }
                let _ = self.sock.send_to(pkt, SocketAddrV6::new(GROUP_V6, PORT, 0, idx));
            }
        }
    }
}

// ── responder ──

/// What the running responder is doing (`lan.status`, `seagent doctor`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Status {
    /// UDP 5353 could not be shared for either family: announcing only, not answering.
    pub limited: bool,
    /// Why it is limited, or which family could not get 5353; empty when all is well.
    pub detail: String,
    /// Shared 5353 sockets per family.
    pub ipv4: bool,
    pub ipv6: bool,
    /// Interfaces it runs on (`eth0`, `Wi-Fi`).
    pub interfaces: Vec<String>,
    /// Every address it currently advertises (`192.168.1.20`, `fe80::1%eth0`).
    pub addrs: Vec<String>,
}

static STATUS: Mutex<Option<Status>> = Mutex::new(None);

/// The status of this process's responder, `None` when none runs.
pub fn responder_status() -> Option<Status> {
    STATUS.lock().ok().and_then(|s| s.clone())
}

fn publish(s: Option<Status>) {
    if let Ok(mut g) = STATUS.lock() {
        *g = s;
    }
}

const LIMITED: &str = "UDP port 5353 is held exclusively by another program, so this host announces itself but cannot answer queries; devices can still pair by address or QR code";

/// Can this process share UDP 5353 (for either family)? `Err` says why discovery is limited.
pub fn port_shareable() -> Result<(), String> {
    match (sock::shared(Fam::V4), sock::shared(Fam::V6)) {
        (Ok(_), _) | (_, Ok(_)) => Ok(()),
        (Err(e), _) => Err(format!("{LIMITED} ({e})")),
    }
}

/// A running responder; dropping it sends the goodbye.
pub struct Responder {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    status: Status,
}

struct State {
    svc: Service,
    nets: Vec<Net>,
    ifaces: Vec<Iface>,
}

impl State {
    fn status(&self) -> Status {
        let shared = |f: Fam| self.nets.iter().any(|n| n.shared && n.fam == f);
        let (ipv4, ipv6) = (shared(Fam::V4), shared(Fam::V6));
        let detail = match (ipv4, ipv6) {
            (false, false) => LIMITED.to_string(),
            (true, false) => "IPv6: UDP [::]:5353 could not be shared; discovery runs over IPv4 only".into(),
            (false, true) => "IPv4: UDP 0.0.0.0:5353 could not be shared; discovery runs over IPv6 only".into(),
            _ if self.ifaces.is_empty() => "no up, multicast-capable network interface yet".into(),
            _ => String::new(),
        };
        let mut addrs: Vec<String> = Vec::new();
        for i in &self.ifaces {
            for a in answer_addrs(&self.svc, &self.ifaces, Some(i)) {
                let s = HostAddr::on(a, i.index).to_string();
                if !addrs.contains(&s) {
                    addrs.push(s);
                }
            }
        }
        Status { limited: !ipv4 && !ipv6, detail, ipv4, ipv6, interfaces: self.ifaces.iter().map(|i| i.name.clone()).collect(), addrs }
    }

    /// Announce (or say goodbye, `ttl` 0) on every interface, each with its own addresses.
    fn announce(&self, ttl: Option<u32>) {
        if self.ifaces.is_empty() {
            let pkt = encode_answer(&self.svc, &answer_addrs(&self.svc, &[], None), 0, ttl, false);
            self.nets.iter().for_each(|n| n.send_group(None, &pkt));
        }
        for i in &self.ifaces {
            let pkt = encode_answer(&self.svc, &answer_addrs(&self.svc, &self.ifaces, Some(i)), 0, ttl, false);
            self.nets.iter().for_each(|n| n.send_group(Some(i), &pkt));
        }
    }

    /// Take a fresh interface list; `true` when it changed (groups re-joined).
    fn rescan(&mut self, fresh: Vec<Iface>) -> bool {
        if fresh == self.ifaces {
            return false;
        }
        self.ifaces = fresh;
        for n in &mut self.nets {
            n.sync(&self.ifaces);
        }
        true
    }

    fn answer(&self, net: &Net, buf: &[u8], from: SocketAddr) {
        let Some(m) = parse(buf) else { return };
        if !asks_for(&m, &self.svc) {
            return;
        }
        let arrival = iface::arrival(&self.ifaces, &from);
        let addrs = answer_addrs(&self.svc, &self.ifaces, arrival);
        if from.port() != PORT {
            // Legacy unicast (a plain resolver or our own browser): answer the asker directly,
            // TTL at most 10 s (RFC 6762 §6.7).
            let _ = net.sock.send_to(&encode_answer(&self.svc, &addrs, m.id, Some(10), true), from);
            return;
        }
        let pkt = encode_answer(&self.svc, &addrs, 0, None, false);
        if m.questions.iter().any(|q| q.2) {
            let _ = net.sock.send_to(&pkt, from);
        } else if arrival.is_some() {
            net.send_group(arrival, &pkt);
        } else {
            self.announce(None);
        }
    }
}

impl Responder {
    /// Bind, join, announce and answer in a background thread. Falls back to a limited
    /// (announce-only) responder when UDP 5353 cannot be shared; errors only when no socket
    /// at all can be opened.
    pub fn start(svc: Service) -> Result<Responder, String> {
        let mut nets: Vec<Net> = [Fam::V4, Fam::V6].into_iter().filter_map(|f| Net::open(f, true).ok()).collect();
        if nets.is_empty() {
            nets = [Fam::V4, Fam::V6].into_iter().filter_map(|f| Net::open(f, false).ok()).collect();
        }
        if nets.is_empty() {
            return Err("mDNS: cannot open a UDP socket; this host will not be discoverable, but devices can still pair by address or QR code".into());
        }
        for n in &nets {
            n.sock.set_read_timeout(Some(Duration::from_millis(125))).map_err(|e| e.to_string())?;
        }
        let mut st = State { svc, nets, ifaces: Vec::new() };
        st.rescan(iface::suitable(iface::system()));
        let status = st.status();
        publish(Some(status.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new().name("seagent-mdns".into()).spawn(move || serve(st, flag)).map_err(|e| e.to_string())?;
        Ok(Responder { stop, thread: Some(thread), status })
    }

    /// The status at start (the live one: [`responder_status`]).
    pub fn status(&self) -> &Status {
        &self.status
    }

    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
            publish(None);
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.halt();
    }
}

fn serve(mut st: State, stop: Arc<AtomicBool>) {
    st.announce(None);
    let mut next_announce = Some(Instant::now() + Duration::from_secs(1));
    let mut next_scan = Instant::now() + RESCAN;
    let mut buf = [0u8; 9000];
    let limited = st.nets.iter().all(|n| !n.shared);
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        if next_announce.is_some_and(|t| now >= t) {
            st.announce(None);
            next_announce = None;
        }
        if now >= next_scan {
            next_scan = now + RESCAN;
            if st.rescan(iface::suitable(iface::system())) {
                publish(Some(st.status()));
                st.announce(None);
                next_announce = Some(now + Duration::from_secs(1));
            } else if limited {
                st.announce(None);
            }
        }
        for n in &st.nets {
            if let Ok((len, from)) = n.sock.recv_from(&mut buf) {
                if n.shared {
                    st.answer(n, &buf[..len], from);
                }
            }
        }
    }
    st.announce(Some(0));
}

// ── browser ──

/// An address of a found host. `scope`: the interface index (zone) an IPv6 link-local address
/// was heard on; 0 otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAddr {
    pub ip: IpAddr,
    pub scope: u32,
}

impl HostAddr {
    /// `ip` heard on interface `index` (the zone is kept only for IPv6 link-local).
    pub fn on(ip: IpAddr, index: u32) -> HostAddr {
        let scope = match ip {
            IpAddr::V6(v6) if iface::is_v6_link_local(&v6) => index,
            _ => 0,
        };
        HostAddr { ip, scope }
    }

    pub fn is_link_local(&self) -> bool {
        match self.ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => iface::is_v6_link_local(&v6),
        }
    }

    /// Preference: private IPv4, routable IPv6 (global / ULA), IPv4 link-local, IPv6 link-local.
    pub fn rank(&self) -> u8 {
        match (self.ip.is_ipv4(), self.is_link_local()) {
            (true, false) => 0,
            (false, false) => 1,
            (true, true) => 2,
            (false, true) => 3,
        }
    }

    pub fn socket_addr(&self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, self.scope)),
        }
    }

    /// `host:port` for a CLI / address field: `192.168.1.20:8640`, `[fe80::1%eth0]:8640`.
    pub fn authority(&self, port: u16) -> String {
        if self.ip.is_ipv4() { format!("{self}:{port}") } else { format!("[{self}]:{port}") }
    }

    /// The URL form (RFC 6874: the zone separator is written `%25`): `https://[fe80::1%25eth0]:8640`.
    pub fn url(&self, scheme: &str, port: u16) -> String {
        format!("{scheme}://{}", self.authority(port).replacen('%', "%25", 1))
    }
}

impl std::fmt::Display for HostAddr {
    /// `192.168.1.20`, `fd00::2`, `fe80::1%eth0` (`%12` on Windows).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.ip, self.scope) {
            (IpAddr::V6(v6), s) if s != 0 => write!(f, "{v6}%{}", iface::zone_name(s)),
            (ip, _) => write!(f, "{ip}"),
        }
    }
}

/// A host found by [`browse`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Found {
    pub instance: String,
    pub host: String,
    pub port: u16,
    /// Preferred first ([`HostAddr::rank`]).
    pub addrs: Vec<HostAddr>,
    pub txt: BTreeMap<String, String>,
}

impl Found {
    /// The address to dial: the best-ranked one.
    pub fn best(&self) -> Option<&HostAddr> {
        self.addrs.first()
    }
}

/// Fold the records of one or more responses into hosts. Each record comes with the zone of
/// the interface its packet arrived on (0: unknown); an IPv6 link-local address with no zone
/// is unusable and dropped.
pub fn collect(records: &[(Record, u32)]) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    let svc = SERVICE.to_ascii_lowercase();
    for (r, _) in records {
        if let (true, RData::Ptr(inst)) = (r.name.to_ascii_lowercase() == svc, &r.data) {
            if r.ttl > 0 && !out.iter().any(|f| f.instance.eq_ignore_ascii_case(inst)) {
                out.push(Found { instance: inst.clone(), ..Default::default() });
            }
        }
    }
    for f in &mut out {
        for (r, _) in records.iter().filter(|(r, _)| r.name.eq_ignore_ascii_case(&f.instance)) {
            match &r.data {
                RData::Srv { port, target } => {
                    f.port = *port;
                    f.host = target.clone();
                }
                RData::Txt(t) => f.txt = t.iter().cloned().collect(),
                _ => {}
            }
        }
        for (r, scope) in records.iter().filter(|(r, _)| !f.host.is_empty() && r.name.eq_ignore_ascii_case(&f.host)) {
            if let RData::Addr(a) = r.data {
                let h = HostAddr::on(a, *scope);
                let unusable = a.is_loopback() || a.is_unspecified() || (h.ip.is_ipv6() && h.is_link_local() && h.scope == 0);
                if !unusable && r.ttl > 0 && !f.addrs.contains(&h) {
                    f.addrs.push(h);
                }
            }
        }
        f.addrs.sort_by_key(HostAddr::rank);
        // `<instance>._seagent._tcp.local` → the readable instance label.
        if let Some(label) = f.instance.strip_suffix(&format!(".{SERVICE}")) {
            f.instance = label.to_string();
        }
    }
    out.retain(|f| f.port != 0);
    out
}

/// Look for `_seagent._tcp` hosts for `timeout`, over IPv4 and IPv6 on every interface.
pub fn browse(timeout: Duration) -> Result<Vec<Found>, String> {
    browse_on(timeout, true, true)
}

/// [`browse`] limited to the address families asked for.
pub fn browse_on(timeout: Duration, v4: bool, v6: bool) -> Result<Vec<Found>, String> {
    let fams: Vec<Fam> = [(Fam::V4, v4), (Fam::V6, v6)].into_iter().filter(|f| f.1).map(|f| f.0).collect();
    let ifaces = iface::suitable(iface::system());
    let mut queriers: Vec<Net> = Vec::new();
    let mut first_err = None;
    for f in &fams {
        match Net::open(*f, false) {
            Ok(n) => queriers.push(n),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    if queriers.is_empty() {
        return Err(format!("mDNS: {}", first_err.map(|e| e.to_string()).unwrap_or_else(|| "no address family to browse".into())));
    }
    let mut listeners: Vec<Net> = fams.iter().filter_map(|f| Net::open(*f, true).ok()).collect();
    for l in &mut listeners {
        l.sync(&ifaces);
    }
    let id = u16::from_be_bytes([crate::crypto::random_bytes(1)[0], crate::crypto::random_bytes(1)[0]]);
    // From an ephemeral port: a legacy query, answered by unicast to us (the QU bit asks the
    // same of responders that look at it). From 5353: a plain multicast query.
    let legacy = encode_query(id, SERVICE, T_PTR, true);
    let multicast = encode_query(id, SERVICE, T_PTR, false);
    let send = || {
        let targets: Vec<Option<&Iface>> = if ifaces.is_empty() { vec![None] } else { ifaces.iter().map(Some).collect() };
        for i in targets {
            queriers.iter().for_each(|q| q.send_group(i, &legacy));
            listeners.iter().for_each(|l| l.send_group(i, &multicast));
        }
    };
    send();
    let until = Instant::now() + timeout;
    let mut records: Vec<(Record, u32)> = Vec::new();
    let mut buf = [0u8; 9000];
    let mut resent = false;
    while Instant::now() < until {
        if !resent && Instant::now() + timeout / 2 >= until {
            send();
            resent = true;
        }
        for n in queriers.iter().chain(listeners.iter()) {
            let _ = n.sock.set_read_timeout(Some(Duration::from_millis(50)));
            while let Ok((len, from)) = n.sock.recv_from(&mut buf) {
                if let Some(m) = parse(&buf[..len]).filter(|m| m.response) {
                    let scope = iface::scope_for(&ifaces, &from).unwrap_or(0);
                    records.extend(m.records.into_iter().map(|r| (r, scope)));
                }
            }
        }
    }
    Ok(collect(&records))
}

#[cfg(test)]
mod tests;
