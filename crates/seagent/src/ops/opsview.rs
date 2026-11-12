//! `ui.ops.status`: the operations overview of the web console — this host (CPU, memory,
//! disk, network, load), the daemon process, every agent (sessions with their parent links,
//! so the UI can draw the delegation tree), today's spend, alerts and the audit tail.
//!
//! One call returns everything the overview needs; the UI polls it every few seconds. Each
//! call also appends one sample to a short in-memory series (CPU, memory, load, running
//! agents, network rates) so the console can draw trends without a metrics store. Reads
//! only: `/proc`, `statvfs`, the session store, the usage ledger and the audit file.

use super::ui_methods::UiCtx;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Samples kept for the trend lines (at the UI's 3 s poll: about six minutes).
const SERIES_LEN: usize = 120;

#[derive(Clone, Copy, Default)]
struct CpuTimes {
    busy: u64,
    total: u64,
}

#[derive(Default)]
struct Sampler {
    cpu: Option<CpuTimes>,
    net: Option<(u64, u64, u64)>,
    series: VecDeque<Value>,
}

fn sampler() -> &'static Mutex<Sampler> {
    static S: OnceLock<Mutex<Sampler>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// When this process first served the overview (≈ daemon start; `seagent daemon run` registers
/// the methods at startup and [`mark_started`] is called there).
fn started_ms() -> u64 {
    static T: OnceLock<u64> = OnceLock::new();
    *T.get_or_init(seagent_kernel::event::now_ms)
}

pub fn mark_started() {
    started_ms();
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn cpu_times(stat: &str) -> Option<CpuTimes> {
    let f: Vec<u64> = stat.lines().next()?.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    if f.len() < 4 {
        return None;
    }
    // user nice system idle iowait irq softirq steal …; idle + iowait are not busy.
    let idle = f[3] + f.get(4).copied().unwrap_or(0);
    let total: u64 = f.iter().take(8).sum();
    Some(CpuTimes { busy: total.saturating_sub(idle), total })
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn meminfo(s: &str) -> (u64, u64, u64, u64) {
    let get = |k: &str| s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) * 1024;
    (get("MemTotal:"), get("MemAvailable:"), get("SwapTotal:"), get("SwapFree:"))
}

/// rx, tx bytes over every interface except loopback.
fn net_bytes(s: &str) -> (u64, u64) {
    let mut rx = 0;
    let mut tx = 0;
    for l in s.lines().skip(2) {
        let Some((name, rest)) = l.split_once(':') else { continue };
        if name.trim() == "lo" {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if f.len() >= 9 {
            rx += f[0];
            tx += f[8];
        }
    }
    (rx, tx)
}

/// (available, total) bytes (`GetDiskFreeSpaceExW` through `platform::sysinfo`).
#[cfg(not(unix))]
fn space(p: &Path) -> Option<(u64, u64)> {
    seagent_core::platform::sysinfo::disk_space(p).ok().map(|d| (d.available, d.total))
}

#[cfg(unix)]
fn space(p: &Path) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid NUL-terminated path and an out-pointer to a zeroed statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some((s.f_bavail as u64 * s.f_frsize as u64, s.f_blocks as u64 * s.f_frsize as u64))
}

fn os_name() -> String {
    read("/etc/os-release").lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim_matches('"').to_string()).unwrap_or_else(|| std::env::consts::OS.to_string())
}

/// This process: resident memory, threads, open descriptors.
fn proc_self() -> Value {
    let status = read("/proc/self/status");
    let field = |k: &str| status.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0);
    json!({"pid": std::process::id(), "rss_bytes": field("VmRSS:") * 1024, "threads": field("Threads:"), "fds": fds})
}

/// Host metrics and one series sample; rates are per second since the previous call.
fn host(c: &UiCtx, running: usize, now: u64) -> Value {
    let cpu_now = cpu_times(&read("/proc/stat"));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let (mt, ma, st, sf) = meminfo(&read("/proc/meminfo"));
    // No /proc here: memory from platform::sysinfo, swap unknown (0); CPU / load / network
    // stay 0 until a per-OS sampler exists.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let (mt, ma, st, sf) = (seagent_core::platform::sysinfo::total_memory().unwrap_or(0), seagent_core::platform::sysinfo::available_memory().unwrap_or(0), 0u64, 0u64);
    let load: Vec<f64> = read("/proc/loadavg").split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    let uptime = read("/proc/uptime").split_whitespace().next().and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    let (rx, tx) = net_bytes(&read("/proc/net/dev"));
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let mut g = sampler().lock().unwrap_or_else(|e| e.into_inner());
    let cpu_pct = match (g.cpu, cpu_now) {
        (Some(a), Some(b)) if b.total > a.total => (b.busy.saturating_sub(a.busy)) as f64 * 100.0 / (b.total - a.total) as f64,
        _ => 0.0,
    };
    let (rx_rate, tx_rate) = match g.net {
        Some((t0, r0, x0)) if now > t0 => {
            let dt = (now - t0) as f64 / 1000.0;
            (rx.saturating_sub(r0) as f64 / dt, tx.saturating_sub(x0) as f64 / dt)
        }
        _ => (0.0, 0.0),
    };
    g.cpu = cpu_now.or(g.cpu);
    g.net = Some((now, rx, tx));
    let mem_pct = if mt > 0 { (mt - ma.min(mt)) as f64 * 100.0 / mt as f64 } else { 0.0 };
    g.series.push_back(json!({"ts": now, "cpu": round1(cpu_pct), "mem": round1(mem_pct), "load": load.first().copied().unwrap_or(0.0), "agents": running, "rx": rx_rate.round(), "tx": tx_rate.round()}));
    while g.series.len() > SERIES_LEN {
        g.series.pop_front();
    }
    let disks: Vec<Value> = [("data", &c.paths.data), ("config", &c.paths.config_dir), ("workspace", &c.ws)]
        .iter()
        .filter_map(|(label, p)| space(p).map(|(free, total)| json!({"label": label, "path": p.display().to_string(), "free": free, "total": total})))
        .collect();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let hostname = read("/proc/sys/kernel/hostname").trim().to_string();
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let hostname = seagent_core::platform::sysinfo::hostname();
    json!({
        "hostname": hostname,
        "os": os_name(),
        "kernel": read("/proc/sys/kernel/osrelease").trim(),
        "arch": std::env::consts::ARCH,
        "cpus": cpus,
        "cpu_pct": round1(cpu_pct),
        "load": load,
        "uptime_s": uptime as u64,
        "mem": {"total": mt, "available": ma, "pct": round1(mem_pct)},
        "swap": {"total": st, "free": sf},
        "net": {"rx_bps": rx_rate.round(), "tx_bps": tx_rate.round()},
        "disks": disks,
    })
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The newest `n` records of the live audit segment (reads only its tail).
fn audit_tail(data: &Path, n: usize) -> Vec<Value> {
    use std::io::{Read, Seek, SeekFrom};
    let p = seagent_security::audit::dir(data).join("events.jsonl");
    let Ok(mut f) = std::fs::File::open(&p) else { return vec![] };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let from = len.saturating_sub(256 * 1024);
    if f.seek(SeekFrom::Start(from)).is_err() {
        return vec![];
    }
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let mut lines: Vec<&str> = s.lines().collect();
    if from > 0 && !lines.is_empty() {
        lines.remove(0); // partial first line
    }
    let mut v: Vec<Value> = lines.iter().rev().filter_map(|l| serde_json::from_str::<Value>(l).ok()).take(n).collect();
    v.reverse();
    v.into_iter()
        .map(|r| json!({"seq": r["seq"], "ts": r["ts"], "kind": r["kind"], "actor": r["actor"], "target": r["target"], "outcome": r["outcome"], "session": r["session"]}))
        .collect()
}

pub fn status(c: &UiCtx) -> Value {
    let now = seagent_kernel::event::now_ms();
    let running_ids = c.k.running_ids();
    let metas = c.k.store.list();
    // Agents: running sessions, their ancestors and descendants, plus the most recent others.
    let day_ago = now.saturating_sub(86_400_000);
    let mut agents: Vec<Value> = metas
        .iter()
        .filter(|s| running_ids.contains(&s.id) || s.updated_ms >= day_ago)
        .take(200)
        .map(|s| json!({"id": s.id, "title": s.title, "model": s.model, "parent": s.parent, "running": running_ids.contains(&s.id), "updated_ms": s.updated_ms, "messages": s.messages, "workspace": s.workspace}))
        .collect();
    agents.sort_by_key(|a| std::cmp::Reverse((a["running"].as_bool().unwrap_or(false), a["updated_ms"].as_u64().unwrap_or(0))));
    let today = {
        let since = now - now % 86_400_000;
        let (rows, _) = crate::models_cli::usage_rows(&c.k.cfg, &c.k.store, since, None);
        let cost: f64 = rows.values().map(|r| r.cost).sum();
        let tokens: u64 = rows.values().map(|r| r.input + r.output).sum();
        let calls: u64 = rows.values().map(|r| r.calls).sum();
        // Calls whose model has no price anywhere: their cost is unknown, not $0.
        let unpriced: u64 = rows.values().filter(|r| !r.priced).map(|r| r.calls).sum();
        json!({"cost_usd": (cost * 10_000.0).round() / 10_000.0, "tokens": tokens, "calls": calls, "unpriced_calls": unpriced})
    };
    let host = host(c, running_ids.len(), now);
    let series: Vec<Value> = sampler().lock().map(|g| g.series.iter().cloned().collect()).unwrap_or_default();
    let alerts = super::ui_methods::custodian(c)["alerts"].clone();
    let channels: Vec<Value> = c.live.channels.iter().map(|(n, k)| json!({"name": n, "kind": k})).collect();
    let mcp = c.live.mcp.clone();
    json!({
        "ts": now,
        "host": host,
        "daemon": {
            "version": env!("CARGO_PKG_VERSION"),
            "started_ms": started_ms(),
            "proc": proc_self(),
            "model": c.k.cfg.model.default,
            "paths": {"config": c.paths.config_dir.display().to_string(), "data": c.paths.data.display().to_string(), "runtime": c.paths.runtime.display().to_string()},
        },
        "sessions": {"total": metas.len(), "running": running_ids.len()},
        "agents": agents,
        "today": today,
        "alerts": alerts,
        "channels": channels,
        "mcp": mcp,
        "audit": {"head": seagent_security::audit::head(&c.paths.data), "tail": audit_tail(&c.paths.data, 30)},
        "series": series,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_parsers() {
        let t = cpu_times("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        assert_eq!((t.busy, t.total), (150, 1000));
        let (mt, ma, st, sf) = meminfo("MemTotal:       1000 kB\nMemFree: 1 kB\nMemAvailable:    250 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
        assert_eq!((mt, ma, st, sf), (1_024_000, 256_000, 0, 0));
        let dev = "Inter-|   Receive\n face |bytes\n    lo: 500 1 0 0 0 0 0 0 500 1 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
        assert_eq!(net_bytes(dev), (1000, 2000));
    }

    #[test]
    fn audit_tail_reads_newest_records() {
        let d = seagent_core::tmp::TempDir::new("seagent-opsview");
        for i in 0..5 {
            seagent_security::audit::emit(d.path(), seagent_security::audit::Event::new("app.request", seagent_security::audit::Actor::new("token", "t"), &format!("m{i}"), "ok")).unwrap();
        }
        let t = audit_tail(d.path(), 3);
        assert_eq!(t.len(), 3);
        assert_eq!(t[2]["target"], "m4");
        assert!(t[0]["seq"].as_u64().is_some());
    }
}
