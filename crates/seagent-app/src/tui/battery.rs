//! Host battery read-out for the status bar (Hermes `agent/battery.py`). Linux reads
//! `/sys/class/power_supply` (BAT* capacity/status, AC/ADP/USB `online`); macOS parses
//! `pmset -g batt`; Windows asks `GetSystemPowerStatus`. Everything degrades to "unavailable"; readings are memoised for 8 s
//! because the status bar repaints on every keystroke.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Battery {
    pub available: bool,
    /// Clamped 0–100.
    pub percent: Option<u8>,
    /// `None` when the platform cannot tell.
    pub plugged: Option<bool>,
}

impl Battery {
    pub fn charging(&self) -> bool {
        self.plugged == Some(true)
    }
}

pub const UNAVAILABLE: Battery = Battery { available: false, percent: None, plugged: None };
const TTL: Duration = Duration::from_secs(8);
static CACHE: Mutex<Option<(Instant, Battery)>> = Mutex::new(None);

/// Read a `power_supply` class directory (tests point this at a fake tree).
pub fn read_sysfs(root: &Path) -> Battery {
    let Ok(rd) = std::fs::read_dir(root) else { return UNAVAILABLE };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    let read = |p: &Path, f: &str| std::fs::read_to_string(p.join(f)).ok().map(|s| s.trim().to_string());
    let mut pct: Vec<u8> = vec![];
    let mut status: Option<String> = None;
    let mut ac: Option<bool> = None;
    for e in &entries {
        let kind = read(e, "type").unwrap_or_default();
        if kind == "Battery" {
            // Peripheral batteries (mice, headsets) report scope=Device.
            if read(e, "scope").as_deref() == Some("Device") {
                continue;
            }
            if let Some(c) = read(e, "capacity").and_then(|c| c.parse::<f64>().ok()) {
                pct.push(c.round().clamp(0.0, 100.0) as u8);
            }
            status = status.or(read(e, "status"));
        } else if kind == "Mains" || kind == "USB" || kind.starts_with("USB_") {
            if let Some(o) = read(e, "online") {
                ac = Some(ac.unwrap_or(false) || o == "1");
            }
        }
    }
    if pct.is_empty() {
        return UNAVAILABLE;
    }
    let percent = (pct.iter().map(|p| *p as u32).sum::<u32>() / pct.len() as u32) as u8;
    let plugged = match status.as_deref() {
        Some("Charging") | Some("Full") => Some(true),
        Some("Discharging") => Some(false),
        _ => ac,
    };
    Battery { available: true, percent: Some(percent), plugged }
}

/// `pmset -g batt` output: `… 'AC Power' … -InternalBattery-0 (id=…) 82%; charging; …`.
pub fn parse_pmset(out: &str) -> Battery {
    let Some(line) = out.lines().find(|l| l.contains("InternalBattery") || (l.contains('%') && l.contains(';'))) else { return UNAVAILABLE };
    let Some(pct) = line.split(|c: char| c.is_whitespace() || c == '\t').find_map(|w| w.strip_suffix("%;").or(w.strip_suffix('%')).and_then(|n| n.parse::<u8>().ok())) else { return UNAVAILABLE };
    let plugged = if out.contains("'AC Power'") {
        Some(true)
    } else if out.contains("'Battery Power'") {
        Some(false)
    } else {
        None
    };
    Battery { available: true, percent: Some(pct.min(100)), plugged }
}

/// `GetSystemPowerStatus`: battery percent and AC line state.
#[cfg(windows)]
fn read_windows() -> Battery {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    // SAFETY: zeroed POD out-parameter.
    let mut s: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: `s` is a valid SYSTEM_POWER_STATUS.
    if unsafe { GetSystemPowerStatus(&mut s) } == 0 || s.BatteryFlag & 128 != 0 || s.BatteryFlag == 255 || s.BatteryLifePercent == 255 {
        return UNAVAILABLE;
    }
    let plugged = match s.ACLineStatus {
        1 => Some(true),
        0 => Some(false),
        _ => None,
    };
    Battery { available: true, percent: Some(s.BatteryLifePercent.min(100)), plugged }
}

#[cfg(windows)]
fn read_uncached() -> Battery {
    read_windows()
}

#[cfg(not(windows))]
fn read_uncached() -> Battery {
    if cfg!(target_os = "macos") {
        return seagent_core::platform::proc::command("pmset").args(["-g", "batt"]).output().ok().map(|o| parse_pmset(&String::from_utf8_lossy(&o.stdout))).unwrap_or(UNAVAILABLE);
    }
    read_sysfs(Path::new("/sys/class/power_supply"))
}

pub fn read(use_cache: bool) -> Battery {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if use_cache {
        if let Some((t, b)) = *c {
            if t.elapsed() < TTL {
                return b;
            }
        }
    }
    let b = read_uncached();
    *c = Some((Instant::now(), b));
    b
}

/// good / warn / bad / critical / dim (full battery is "good"; AC power is never a concern).
pub fn category(b: &Battery) -> &'static str {
    let Some(p) = b.percent.filter(|_| b.available) else { return "dim" };
    if b.charging() {
        return "good";
    }
    match p {
        0..=10 => "critical",
        11..=20 => "bad",
        21..=50 => "warn",
        _ => "good",
    }
}

pub fn glyph(b: &Battery) -> &'static str {
    if b.charging() {
        "⚡"
    } else {
        "🔋"
    }
}

/// `🔋 82%` / `⚡ 82%`, empty when unavailable.
pub fn format(b: &Battery) -> String {
    match b.percent.filter(|_| b.available) {
        Some(p) => format!("{} {p}%", glyph(b)),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysfs_pmset_and_categories() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-batt-{}", seagent_kernel::util::random_hex(6)));
        for (d, files) in [("BAT0", vec![("type", "Battery"), ("capacity", "15"), ("status", "Discharging")]), ("AC", vec![("type", "Mains"), ("online", "0")]), ("hidpp_battery_0", vec![("type", "Battery"), ("scope", "Device"), ("capacity", "100")])] {
            std::fs::create_dir_all(root.join(d)).unwrap();
            for (f, v) in files {
                std::fs::write(root.join(d).join(f), format!("{v}\n")).unwrap();
            }
        }
        let b = read_sysfs(&root);
        assert_eq!(b, Battery { available: true, percent: Some(15), plugged: Some(false) });
        assert_eq!(category(&b), "bad");
        assert_eq!(format(&b), "🔋 15%");
        std::fs::write(root.join("BAT0/status"), "Charging\n").unwrap();
        let b = read_sysfs(&root);
        assert!(b.charging());
        assert_eq!(category(&b), "good");
        assert_eq!(format(&b), "⚡ 15%");
        assert_eq!(read_sysfs(&root.join("none")), UNAVAILABLE);
        assert_eq!(format(&UNAVAILABLE), "");
        assert_eq!(category(&UNAVAILABLE), "dim");
        let mac = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1234)\t8%; discharging; 0:20 remaining present: true\n";
        let b = parse_pmset(mac);
        assert_eq!((b.percent, b.plugged), (Some(8), Some(false)));
        assert_eq!(category(&b), "critical");
        assert_eq!(category(&Battery { available: true, percent: Some(40), plugged: Some(false) }), "warn");
    }
}
