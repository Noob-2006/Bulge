//! Small dependency-free helpers the kernel shares: time formatting and date arithmetic
//! (`civil_from_days`), id generation and head/tail truncation.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Format unix seconds with a fixed UTC offset (minutes) as `YYYY-MM-DD HH:MM`.
pub fn fmt_time(unix_secs: i64, offset_min: i32) -> String {
    let t = unix_secs + offset_min as i64 * 60;
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", s / 3600, (s / 60) % 60)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n.div_ceil(2)];
    if fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_err() {
        // Fallback: time + address entropy. Only used for ids, never for secrets.
        let seed = crate::event::now_ms() ^ (&buf as *const _ as u64);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (seed >> ((i % 8) * 8)) as u8 ^ i as u8;
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect::<String>()[..n].to_string()
}

/// Sortable, human-readable id: `20261101-1530-a1b2c3`.
pub fn new_id() -> String {
    let t = unix_now();
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}-{}", s / 3600, (s / 60) % 60, s % 60, random_hex(6))
}

/// Crash-safe file replace: write temp, fsync, rename, fsync dir.
pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.tmp-{}", path.file_name().and_then(|s| s.to_str()).unwrap_or("f"), random_hex(6)));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Truncate to at most `max` bytes on a char boundary, keeping head and tail.
pub fn head_tail(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let half = max / 2;
    let mut h = half;
    while !s.is_char_boundary(h) {
        h -= 1;
    }
    let mut t = s.len() - half;
    while !s.is_char_boundary(t) {
        t += 1;
    }
    let omitted = t - h;
    (format!("{}\n…[{omitted} bytes omitted]…\n{}", &s[..h], &s[t..]), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip() {
        for days in [-1_000_000i64, -1, 0, 1, 19_000, 20_758, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2024, 2, 29) + 1, days_from_civil(2024, 3, 1));
    }

    #[test]
    fn fmt_time_with_offset() {
        assert_eq!(fmt_time(0, 480), "1970-01-01 08:00");
        assert_eq!(fmt_time(-60, 0), "1969-12-31 23:59");
    }

    #[test]
    fn head_tail_respects_char_boundaries() {
        let s = "中文字".repeat(100);
        let (out, cut) = head_tail(&s, 31);
        assert!(cut);
        assert!(out.contains("omitted"));
        let (same, cut2) = head_tail("short", 100);
        assert_eq!(same, "short");
        assert!(!cut2);
    }

    #[test]
    fn ids_are_unique_and_sortable() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("ark-util-{}", random_hex(8)));
        let p = dir.join("x.txt");
        atomic_write(&p, b"one").unwrap();
        atomic_write(&p, b"two").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "two");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
