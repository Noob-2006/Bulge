//! UTC offset of a timezone at an instant, without a tz database dependency: fixed offsets
//! (`UTC`, `UTC+8`, `+05:30`) and IANA names read from the system's TZif files
//! (`/usr/share/zoneinfo`, `$TZDIR`; `local` = `/etc/localtime`), including the POSIX TZ
//! footer rule that covers instants past the last transition (DST `Mm.w.d[/time]` rules).
//! Used for heartbeat active hours and OpenClaw-style `schedule.tz`.

use std::path::PathBuf;

/// Offset in minutes east of UTC for `tz` at unix time `at`; None when unknown.
pub fn offset_minutes(tz: &str, at: i64) -> Option<i32> {
    let tz = tz.trim();
    if let Some(m) = fixed(tz) {
        return Some(m);
    }
    let bytes = if tz.eq_ignore_ascii_case("local") {
        std::fs::read("/etc/localtime").ok()?
    } else {
        if tz.contains("..") || tz.starts_with('/') || !tz.chars().all(|c| c.is_ascii_alphanumeric() || "/_-+".contains(c)) {
            return None;
        }
        let dirs: Vec<PathBuf> = std::env::var_os("TZDIR").map(PathBuf::from).into_iter().chain([PathBuf::from("/usr/share/zoneinfo"), PathBuf::from("/usr/lib/zoneinfo")]).collect();
        dirs.iter().find_map(|d| std::fs::read(d.join(tz)).ok())?
    };
    tzif_offset(&bytes, at).map(|s| (s / 60) as i32)
}

/// `UTC`, `GMT`, `Z`, `UTC+8`, `GMT-03:30`, `+0800`, `-05:00`.
fn fixed(tz: &str) -> Option<i32> {
    let u = tz.to_ascii_uppercase();
    let rest = if matches!(u.as_str(), "UTC" | "GMT" | "Z" | "ETC/UTC" | "ETC/GMT") {
        return Some(0);
    } else if let Some(r) = u.strip_prefix("UTC").or_else(|| u.strip_prefix("GMT")) {
        r
    } else if u.starts_with('+') || u.starts_with('-') {
        u.as_str()
    } else {
        return None;
    };
    let sign = match rest.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let body = rest[1..].replace(':', "");
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let (h, m) = match body.len() {
        1 | 2 => (body.parse::<i32>().ok()?, 0),
        3 => (body[..1].parse::<i32>().ok()?, body[1..].parse::<i32>().ok()?),
        4 => (body[..2].parse::<i32>().ok()?, body[2..].parse::<i32>().ok()?),
        _ => return None,
    };
    (h <= 14 && m < 60).then_some(sign * (h * 60 + m))
}

fn be32(b: &[u8], i: usize) -> Option<i64> {
    Some(i32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?) as i64)
}
fn be64(b: &[u8], i: usize) -> Option<i64> {
    Some(i64::from_be_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

/// Offset (seconds) from a TZif v1/v2/v3 file.
pub fn tzif_offset(b: &[u8], at: i64) -> Option<i64> {
    if b.get(..4)? != b"TZif" {
        return None;
    }
    let version = *b.get(4)?;
    let counts = |base: usize| -> Option<[usize; 6]> {
        let mut c = [0usize; 6];
        for (k, slot) in c.iter_mut().enumerate() {
            *slot = be32(b, base + 20 + k * 4)? as usize;
        }
        Some(c) // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
    };
    let c1 = counts(0)?;
    let v1_len = 44 + c1[3] * 5 + c1[4] * 6 + c1[5] + c1[2] * 8 + c1[1] + c1[0];
    let (base, tsize, c) = if version >= b'2' { (v1_len, 8usize, counts(v1_len)?) } else { (0, 4usize, c1) };
    let [isut, isstd, leap, timecnt, typecnt, charcnt] = c;
    let times = base + 44;
    let idxs = times + timecnt * tsize;
    let types = idxs + timecnt;
    let read_t = |i: usize| if tsize == 8 { be64(b, times + i * 8) } else { be32(b, times + i * 4) };
    let ttinfo = |k: usize| be32(b, types + k * 6);
    let footer_start = types + typecnt * 6 + charcnt + leap * (tsize + 4) + isstd + isut;
    // Last transition at or before `at`.
    let mut last: Option<usize> = None;
    for i in 0..timecnt {
        if read_t(i)? <= at {
            last = Some(i);
        } else {
            break;
        }
    }
    if version >= b'2' && (timecnt == 0 || last == Some(timecnt - 1)) {
        if let Some(f) = b.get(footer_start..) {
            let s = String::from_utf8_lossy(f);
            let rule = s.trim_matches('\n').lines().next().unwrap_or("");
            if !rule.is_empty() {
                if let Some(off) = posix_offset(rule, at) {
                    return Some(off);
                }
            }
        }
    }
    match last {
        Some(i) => ttinfo(*b.get(idxs + i)? as usize),
        None => {
            // Before the first transition: the first non-DST type (RFC 8536 §3.2).
            (0..typecnt).find(|k| b.get(types + k * 6 + 4) == Some(&0)).or((typecnt > 0).then_some(0)).and_then(ttinfo)
        }
    }
}

/// POSIX TZ string (`CST-8`, `EST5EDT,M3.2.0,M11.1.0`, `<+0330>-3:30`) → offset seconds east.
pub fn posix_offset(rule: &str, at: i64) -> Option<i64> {
    let mut p = rule;
    let name = |p: &mut &str| -> Option<()> {
        if let Some(r) = p.strip_prefix('<') {
            let end = r.find('>')?;
            *p = &r[end + 1..];
        } else {
            let n = p.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(p.len());
            if n < 3 {
                return None;
            }
            *p = &p[n..];
        }
        Some(())
    };
    let hms = |p: &mut &str| -> Option<i64> {
        let mut sign = 1;
        if let Some(r) = p.strip_prefix('-') {
            sign = -1;
            *p = r;
        } else if let Some(r) = p.strip_prefix('+') {
            *p = r;
        }
        let n = p.find(|c: char| !(c.is_ascii_digit() || c == ':')).unwrap_or(p.len());
        let (num, rest) = p.split_at(n);
        *p = rest;
        let mut parts = num.split(':').map(|x| x.parse::<i64>());
        let h = parts.next()?.ok()?;
        let m = parts.next().transpose().ok()?.unwrap_or(0);
        let s = parts.next().transpose().ok()?.unwrap_or(0);
        Some(sign * (h * 3600 + m * 60 + s))
    };
    name(&mut p)?;
    let std_off = -hms(&mut p)?; // POSIX offsets are west-positive
    if p.is_empty() {
        return Some(std_off);
    }
    name(&mut p)?;
    let dst_off = if p.starts_with(',') { std_off + 3600 } else { -hms(&mut p)? };
    let p = p.strip_prefix(',')?;
    let (start, end) = p.split_once(',')?;
    let (y, _, _) = crate::util::civil_from_days((at + std_off).div_euclid(86_400));
    let s = rule_instant(start, y)? - std_off;
    let e = rule_instant(end, y)? - dst_off;
    let in_dst = if s < e { at >= s && at < e } else { at >= s || at < e };
    Some(if in_dst { dst_off } else { std_off })
}

/// `Mm.w.d[/time]` (also `Jn`, `n`) → local seconds since epoch in year `y`.
fn rule_instant(r: &str, y: i64) -> Option<i64> {
    let (date, time) = r.split_once('/').unwrap_or((r, "2"));
    let secs = {
        let (sign, t) = time.strip_prefix('-').map(|t| (-1, t)).unwrap_or((1, time));
        let mut it = t.split(':').map(|x| x.parse::<i64>().unwrap_or(0));
        sign * (it.next()? * 3600 + it.next().unwrap_or(0) * 60 + it.next().unwrap_or(0))
    };
    let jan1 = crate::util::days_from_civil(y, 1, 1);
    let day = if let Some(m) = date.strip_prefix('M') {
        let mut f = m.split('.').map(|x| x.parse::<i64>());
        let (mo, w, d) = (f.next()?.ok()?, f.next()?.ok()?, f.next()?.ok()?);
        let first = crate::util::days_from_civil(y, mo as u32, 1);
        let wd_first = (first + 4).rem_euclid(7);
        let mut day = first + (d - wd_first).rem_euclid(7) + (w - 1) * 7;
        let next_month = if mo == 12 { crate::util::days_from_civil(y + 1, 1, 1) } else { crate::util::days_from_civil(y, mo as u32 + 1, 1) };
        while day >= next_month {
            day -= 7;
        }
        day
    } else if let Some(j) = date.strip_prefix('J') {
        // 1..365, Feb 29 never counted.
        let n: i64 = j.parse().ok()?;
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        jan1 + n - 1 + i64::from(leap && n >= 60)
    } else {
        jan1 + date.parse::<i64>().ok()?
    };
    Some(day * 86_400 + secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::days_from_civil;

    #[test]
    fn fixed_offsets_and_posix_rules() {
        assert_eq!(offset_minutes("UTC", 0), Some(0));
        assert_eq!(offset_minutes("UTC+8", 0), Some(480));
        assert_eq!(offset_minutes("GMT-03:30", 0), Some(-210));
        assert_eq!(offset_minutes("+0530", 0), Some(330));
        assert_eq!(offset_minutes("../etc/passwd", 0), None);
        assert_eq!(offset_minutes("Not/AZone", 0), None);
        assert_eq!(posix_offset("CST-8", 0), Some(8 * 3600));
        let summer = days_from_civil(2026, 7, 1) * 86_400;
        let winter = days_from_civil(2026, 1, 15) * 86_400;
        assert_eq!(posix_offset("EST5EDT,M3.2.0,M11.1.0", summer), Some(-4 * 3600));
        assert_eq!(posix_offset("EST5EDT,M3.2.0,M11.1.0", winter), Some(-5 * 3600));
        // Southern hemisphere: DST spans the new year.
        assert_eq!(posix_offset("AEST-10AEDT,M10.1.0,M4.1.0/3", winter), Some(11 * 3600));
        assert_eq!(posix_offset("<+0330>-3:30", 0), Some(12_600));
        // US 2026 DST starts Sunday 8 March 02:00 local.
        let before = days_from_civil(2026, 3, 8) * 86_400 + 6 * 3600 + 59 * 60; // 01:59 EST
        assert_eq!(posix_offset("EST5EDT,M3.2.0,M11.1.0", before), Some(-5 * 3600));
        assert_eq!(posix_offset("EST5EDT,M3.2.0,M11.1.0", before + 120), Some(-4 * 3600));
    }

    #[test]
    fn tzif_from_system_and_synthetic() {
        // Synthetic v1 file: one transition at t=1000 from +0 (type 0) to +3600 (type 1).
        let mut f = b"TZif".to_vec();
        f.push(0);
        f.extend([0u8; 15]);
        for n in [0u32, 0, 0, 1, 2, 4] {
            f.extend(n.to_be_bytes());
        }
        f.extend(1000i32.to_be_bytes());
        f.push(1);
        f.extend(0i32.to_be_bytes());
        f.extend([0, 0]);
        f.extend(3600i32.to_be_bytes());
        f.extend([1, 0]);
        f.extend(b"UTC\0");
        assert_eq!(tzif_offset(&f, 10), Some(0));
        assert_eq!(tzif_offset(&f, 5000), Some(3600));
        assert_eq!(tzif_offset(b"nope", 0), None);
        if std::path::Path::new("/usr/share/zoneinfo/Asia/Taipei").exists() {
            assert_eq!(offset_minutes("Asia/Taipei", days_from_civil(2026, 7, 1) * 86_400), Some(480));
        }
        if std::path::Path::new("/usr/share/zoneinfo/America/New_York").exists() {
            assert_eq!(offset_minutes("America/New_York", days_from_civil(2030, 7, 1) * 86_400), Some(-240));
            assert_eq!(offset_minutes("America/New_York", days_from_civil(2030, 1, 1) * 86_400), Some(-300));
        }
    }
}
