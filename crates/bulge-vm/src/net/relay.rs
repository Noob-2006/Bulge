//! Frame relay between the VMM and passt (QEMU stream framing: u32 BE length +
//! Ethernet frame). Guest->net frames are filtered; net->guest frames pass.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::frame::{Verdict, inspect_guest_frame};
use super::policy::EgressPolicy;

/// Largest frame either side may send (passt's own limit is 65520 + headers).
const MAX_FRAME: usize = 65_550;
const HOST_ADDR_REFRESH: Duration = Duration::from_secs(5);
/// Most recent distinct dropped destinations kept for the audit view.
const RECENT_DROPS: usize = 64;

#[derive(Debug, Default)]
pub struct RelayStats {
    pub passed: AtomicU64,
    pub dropped: AtomicU64,
    recent: Mutex<Vec<IpAddr>>,
}

impl RelayStats {
    pub fn recent_drops(&self) -> Vec<IpAddr> {
        self.recent.lock().map(|r| r.clone()).unwrap_or_default()
    }

    fn record_drop(&self, dst: Option<IpAddr>) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        let (Some(dst), Ok(mut recent)) = (dst, self.recent.lock()) else { return };
        if !recent.contains(&dst) {
            if recent.len() == RECENT_DROPS {
                recent.remove(0);
            }
            recent.push(dst);
        }
    }
}

pub struct RelayHandle {
    pub stats: Arc<RelayStats>,
    stop: Arc<AtomicBool>,
    vm: UnixStream,
    net: UnixStream,
    threads: Vec<JoinHandle<()>>,
}

impl RelayHandle {
    /// Stop relaying and wait for both directions to finish. The real work lives
    /// in `Drop`, so a `RelayHandle` that is simply dropped (an error path, a
    /// panic) is cleaned up exactly the same way — no leaked relay threads.
    pub fn shutdown(self) {}

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Closing both sockets unblocks the threads' blocking reads so they exit.
        let _ = self.vm.shutdown(Shutdown::Both);
        let _ = self.net.shutdown(Shutdown::Both);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// `vm` is our end of the socketpair handed to libkrun; `net` is our end of
/// the socketpair handed to passt (`--fd`).
pub fn spawn_relay(vm: UnixStream, net: UnixStream, policy: EgressPolicy) -> io::Result<RelayHandle> {
    let stats = Arc::new(RelayStats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let policy = Arc::new(RwLock::new(policy));

    let egress = {
        let (mut from, mut to) = (vm.try_clone()?, net.try_clone()?);
        let (stats, stop, policy) = (stats.clone(), stop.clone(), policy.clone());
        std::thread::Builder::new().name("bulge-net-egress".into()).spawn(move || {
            let mut buf = vec![0u8; MAX_FRAME];
            let mut refreshed = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                let Ok(len) = read_frame(&mut from, &mut buf) else { break };
                if refreshed.elapsed() >= HOST_ADDR_REFRESH {
                    if let Ok(mut p) = policy.write() {
                        p.refresh_host_addrs();
                    }
                    refreshed = Instant::now();
                }
                let verdict = match policy.read() {
                    Ok(p) => inspect_guest_frame(&buf[..len], &p),
                    Err(_) => Verdict::Drop { dst: None },
                };
                match verdict {
                    Verdict::Pass => {
                        stats.passed.fetch_add(1, Ordering::Relaxed);
                        if write_frame(&mut to, &buf[..len]).is_err() {
                            break;
                        }
                    }
                    Verdict::Drop { dst } => stats.record_drop(dst),
                }
            }
            let _ = to.shutdown(Shutdown::Both);
        })?
    };

    let ingress = {
        let (mut from, mut to) = (net.try_clone()?, vm.try_clone()?);
        let stop = stop.clone();
        std::thread::Builder::new().name("bulge-net-ingress".into()).spawn(move || {
            let mut buf = vec![0u8; MAX_FRAME];
            while !stop.load(Ordering::Relaxed) {
                let Ok(len) = read_frame(&mut from, &mut buf) else { break };
                if write_frame(&mut to, &buf[..len]).is_err() {
                    break;
                }
            }
            let _ = to.shutdown(Shutdown::Both);
        })?
    };

    Ok(RelayHandle { stats, stop, vm, net, threads: vec![egress, ingress] })
}

fn read_frame(stream: &mut UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length out of range"));
    }
    stream.read_exact(&mut buf[..len])?;
    Ok(len)
}

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> io::Result<()> {
    let len = u32::try_from(frame.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(frame)
}
