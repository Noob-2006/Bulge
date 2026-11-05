//! Schedule grammar shared by the `cronjob_manage` / `automations` tools, `/loop` and
//! suggestions (Hermes `cron/jobs.py::parse_schedule`, OpenClaw `schedule.kind`):
//!
//! - recurring interval: `30m`, `every 2h`, `every hour`
//! - one-shot by duration: `in 30m`, `in 2h`
//! - natural day/time: `every monday 9am`, `weekdays at 9am`, `every day at 9am`
//! - cron syntax: `0 9 * * *` (and ark's `@every 15m` / `@daily` macros)
//! - absolute one-shot: ISO timestamp `2026-06-01T09:00:00` (naive = the configured UTC offset)
//!
//! One-shots are stored with the expression `@once <iso>`: the scheduler cannot compute a next
//! fire for it, so `automation::claim_due` disables the job after its single run.

use crate::cron::Cron;
use crate::util::{civil_from_days, days_from_civil};

#[derive(Debug, Clone, PartialEq)]
pub struct Sched {
    /// What `Job.cron` stores (a `Cron::parse` expression, or `@once <iso>`).
    pub expr: String,
    /// First fire time (unix secs).
    pub first_run: i64,
    pub once: bool,
    /// Human form (`every 30m`, `once in 2h`, `0 9 * * 1-5`…).
    pub display: String,
}

/// Hermes `parse_duration`: minutes from `30m`, `2h`, `1d`, a bare unit (`hour` = 1h).
pub fn parse_duration_minutes(s: &str) -> Result<i64, String> {
    let s = s.trim().to_ascii_lowercase();
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    let unit = s[digits.len()..].trim();
    let mult = match unit {
        "m" | "min" | "mins" | "minute" | "minutes" => 1,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60,
        "d" | "day" | "days" => 1440,
        _ => return Err(format!("Invalid duration: '{s}'. Use format like '30m', '2h', '1d', or a bare unit like 'hour' (defaults to 1).")),
    };
    let n: i64 = if digits.is_empty() { 1 } else { digits.parse().map_err(|_| format!("Invalid duration: '{s}'"))? };
    if n <= 0 {
        return Err(format!("Invalid duration: '{s}' (must be positive)"));
    }
    Ok(n * mult)
}

/// OpenClaw `parseDurationMs`: `90s`, `5m`, `1h30m`, `2d`, a bare number = milliseconds.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse().map_err(|_| format!("bad duration `{s}`"));
    }
    let mut total: u64 = 0;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let mut unit = c.to_string();
        while let Some(&n) = chars.peek() {
            if n.is_ascii_alphabetic() {
                unit.push(n);
                chars.next();
            } else {
                break;
            }
        }
        let v: f64 = num.parse().map_err(|_| format!("bad duration `{s}`"))?;
        num.clear();
        let mult = match unit.as_str() {
            "ms" => 1.0,
            "s" | "sec" | "secs" => 1000.0,
            "m" | "min" | "mins" => 60_000.0,
            "h" | "hr" | "hrs" => 3_600_000.0,
            "d" | "day" | "days" => 86_400_000.0,
            "w" => 604_800_000.0,
            _ => return Err(format!("bad duration unit `{unit}` in `{s}`")),
        };
        total += (v * mult) as u64;
        any = true;
    }
    if !num.is_empty() || !any {
        return Err(format!("bad duration `{s}`"));
    }
    Ok(total)
}

fn weekday(tok: &str) -> Option<&'static str> {
    Some(match tok {
        "sunday" | "sun" => "0",
        "monday" | "mon" => "1",
        "tuesday" | "tue" | "tues" => "2",
        "wednesday" | "wed" | "weds" => "3",
        "thursday" | "thu" | "thur" | "thurs" => "4",
        "friday" | "fri" => "5",
        "saturday" | "sat" => "6",
        _ => return None,
    })
}

/// Hermes `_parse_clock_time`: `9am`, `9:30am`, `14:00`, `7`, `noon`, `midnight`.
pub fn parse_clock(text: &str) -> Option<(u32, u32)> {
    let t: String = text.trim().to_ascii_lowercase().chars().filter(|c| *c != ' ').collect();
    match t.as_str() {
        "" => return None,
        "noon" | "midday" => return Some((12, 0)),
        "midnight" => return Some((0, 0)),
        _ => {}
    }
    let (body, mer) = if let Some(b) = t.strip_suffix("am") { (b, Some(false)) } else if let Some(b) = t.strip_suffix("pm") { (b, Some(true)) } else { (t.as_str(), None) };
    let (h, m) = match body.split_once(':') {
        Some((h, m)) if m.len() == 2 => (h, m),
        Some(_) => return None,
        None => (body, "0"),
    };
    if h.is_empty() || h.len() > 2 || !h.chars().all(|c| c.is_ascii_digit()) || !m.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut hour: u32 = h.parse().ok()?;
    let minute: u32 = m.parse().ok()?;
    if let Some(pm) = mer {
        if !(1..=12).contains(&hour) {
            return None;
        }
        hour = hour % 12 + if pm { 12 } else { 0 };
    }
    (hour <= 23 && minute <= 59).then_some((hour, minute))
}

/// Hermes `_natural_every_to_cron`: `monday 9am`, `weekdays at 9am`, `monday, wednesday at 9am`.
pub fn natural_to_cron(rest: &str) -> Option<String> {
    let lower = rest.to_ascii_lowercase().replace(',', " ");
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    let first = *tokens.first()?;
    let (dow, mut idx) = match first {
        "day" | "daily" | "everyday" => ("*".to_string(), 1),
        "weekday" | "weekdays" => ("1-5".to_string(), 1),
        "weekend" | "weekends" => ("0,6".to_string(), 1),
        _ => {
            let mut days: Vec<&str> = Vec::new();
            let mut idx = tokens.len();
            for (i, tok) in tokens.iter().enumerate() {
                if *tok == "and" {
                    continue;
                }
                match weekday(tok) {
                    Some(d) => {
                        if !days.contains(&d) {
                            days.push(d)
                        }
                    }
                    None => {
                        idx = i;
                        break;
                    }
                }
            }
            if days.is_empty() {
                return None;
            }
            (days.join(","), idx)
        }
    };
    if tokens.get(idx) == Some(&"at") {
        idx += 1;
    }
    if idx >= tokens.len() {
        return None;
    }
    let (h, m) = parse_clock(&tokens[idx..].join(" "))?;
    Some(format!("{m} {h} * * {dow}"))
}

/// `YYYY-MM-DD[T ]HH:MM[:SS][Z|±HH:MM]` → unix secs; naive times use `offset_min`.
pub fn parse_iso(s: &str, offset_min: i32) -> Result<i64, String> {
    let bad = || format!("Invalid timestamp '{s}'");
    let s = s.trim();
    if s.len() < 10 {
        return Err(bad());
    }
    let (date, rest) = s.split_at(10);
    let d: Vec<&str> = date.split('-').collect();
    if d.len() != 3 {
        return Err(bad());
    }
    let y: i64 = d[0].parse().map_err(|_| bad())?;
    let mo: u32 = d[1].parse().map_err(|_| bad())?;
    let da: u32 = d[2].parse().map_err(|_| bad())?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return Err(bad());
    }
    let rest = rest.strip_prefix(['T', 't', ' ']).unwrap_or(rest);
    // Split off the zone designator.
    let (clock, zone) = match rest.find(['Z', 'z', '+']).or_else(|| rest.rfind('-').filter(|i| *i >= 5)) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut hms = [0i64; 3];
    if !clock.is_empty() {
        let clock = clock.split('.').next().unwrap_or(clock);
        for (i, p) in clock.split(':').enumerate() {
            if i > 2 {
                return Err(bad());
            }
            hms[i] = p.parse().map_err(|_| bad())?;
        }
    }
    if hms[0] > 23 || hms[1] > 59 || hms[2] > 60 {
        return Err(bad());
    }
    let off_secs = match zone {
        "" => offset_min as i64 * 60,
        "Z" | "z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let body = z[1..].replace(':', "");
            if body.len() != 4 {
                return Err(bad());
            }
            let h: i64 = body[..2].parse().map_err(|_| bad())?;
            let m: i64 = body[2..].parse().map_err(|_| bad())?;
            sign * (h * 3600 + m * 60)
        }
    };
    let (cy, cm, cd) = civil_from_days(days_from_civil(y, mo, da));
    if (cy, cm, cd) != (y, mo, da) {
        return Err(bad());
    }
    Ok(days_from_civil(y, mo, da) * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms[2] - off_secs)
}

/// Parse a schedule string (see module docs). `now` and `offset_min` fix the clock.
pub fn parse(schedule: &str, now: i64, offset_min: i32) -> Result<Sched, String> {
    let original = schedule.trim();
    let lower = original.to_ascii_lowercase();
    let usage = || {
        format!(
            "Invalid schedule '{original}'. Use:\n  - Interval: '30m', 'every 30m', 'every 2h' (recurring)\n  - One-shot delay: 'in 30m', 'in 2h' (fires once)\n  - Weekly/daily: 'every monday 9am', 'weekdays at 9am' (recurring)\n  - Cron: '0 9 * * *' (cron expression)\n  - Timestamp: '2026-02-03T14:00:00' (one-shot at time)"
        )
    };
    if original.is_empty() {
        return Err(usage());
    }
    let cron = |expr: String, display: String| -> Result<Sched, String> {
        let c = Cron::parse(&expr).map_err(|e| format!("Invalid cron expression '{display}': {e}"))?;
        let first_run = c.next_after(now, offset_min).ok_or_else(|| format!("schedule '{display}' never fires"))?;
        Ok(Sched { expr, first_run, once: false, display })
    };
    let interval = |minutes: i64| Sched { expr: format!("@every {minutes}m"), first_run: now + minutes * 60, once: false, display: format!("every {minutes}m") };
    let once = |at: i64, display: String| -> Result<Sched, String> {
        if at <= now {
            return Err(format!("'{original}' is in the past"));
        }
        Ok(Sched { expr: format!("@once {}", iso_utc(at)), first_run: at, once: true, display })
    };
    let is_every = lower.starts_with("every ");
    let rest = if is_every { lower[6..].trim().to_string() } else { lower.clone() };
    if let Some(expr) = natural_to_cron(&rest) {
        return cron(expr, original.to_string());
    }
    if is_every {
        return parse_duration_minutes(&rest).map(interval);
    }
    if original.starts_with('@') {
        if let Some(at) = original.strip_prefix("@once ") {
            return once(parse_iso(at, 0)?, original.to_string());
        }
        return cron(original.to_string(), original.to_string());
    }
    let parts: Vec<&str> = original.split_whitespace().collect();
    if parts.len() >= 5 && parts[..5].iter().all(|p| p.chars().all(|c| c.is_ascii_alphanumeric() || "*-,/".contains(c))) {
        return cron(parts[..5].join(" "), original.to_string());
    }
    if original.contains('T') || (original.len() >= 10 && original.as_bytes()[4] == b'-' && original[..4].chars().all(|c| c.is_ascii_digit())) {
        let at = parse_iso(original, offset_min)?;
        return once(at, format!("once at {}", crate::util::fmt_time(at, offset_min)));
    }
    if let Some(d) = lower.strip_prefix("in ") {
        let m = parse_duration_minutes(d).map_err(|_| format!("Invalid duration '{}' after 'in '. Use e.g. 'in 30m', 'in 2h'.", d.trim()))?;
        return once(now + m * 60, format!("once in {}", d.trim()));
    }
    parse_duration_minutes(&lower).map(interval).map_err(|_| usage())
}

/// OpenClaw structured schedule (`{kind:"at"|"every"|"cron", at, everyMs, expr}`) → Sched.
pub fn from_openclaw(v: &serde_json::Value, now: i64, offset_min: i32) -> Result<Sched, String> {
    let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or_else(|| if v.get("expr").is_some() { "cron" } else if v.get("everyMs").is_some() { "every" } else { "at" });
    match kind {
        "at" => {
            let at = v.get("at").and_then(|x| x.as_str()).ok_or("schedule.at is required for kind=at")?;
            parse(at, now, offset_min).and_then(|s| if s.once { Ok(s) } else { Err("schedule.at must be an ISO-8601 time".into()) })
        }
        "every" => {
            let ms = v.get("everyMs").and_then(|x| x.as_u64()).ok_or("schedule.everyMs is required for kind=every")?;
            let secs = (ms / 1000) as i64;
            if secs < 60 {
                return Err("schedule.everyMs must be at least 60000 (the scheduler ticks per minute)".into());
            }
            let anchor = v.get("anchorMs").and_then(|x| x.as_i64()).map(|a| a / 1000);
            let first = match anchor {
                Some(a) if a > now => a,
                Some(a) => a + ((now - a) / secs + 1) * secs,
                None => now + secs,
            };
            let expr = if secs % 60 == 0 { format!("@every {}m", secs / 60) } else { format!("@every {secs}s") };
            Ok(Sched { expr, first_run: first, once: false, display: format!("every {}", human_secs(secs)) })
        }
        "cron" => {
            let expr = v.get("expr").and_then(|x| x.as_str()).ok_or("schedule.expr is required for kind=cron")?;
            let mut off = offset_min;
            if let Some(tz) = v.get("tz").and_then(|x| x.as_str()).filter(|t| !t.is_empty()) {
                off = crate::tzfile::offset_minutes(tz, now).ok_or_else(|| format!("unknown timezone `{tz}`"))?;
            }
            let c = Cron::parse(expr).map_err(|e| format!("Invalid cron expression '{expr}': {e}"))?;
            let first_run = c.next_after(now, off).ok_or("that schedule never fires")?;
            Ok(Sched { expr: expr.to_string(), first_run, once: false, display: expr.to_string() })
        }
        k => Err(format!("schedule kind `{k}` is not supported here (at, every, cron)")),
    }
}

pub fn human_secs(s: i64) -> String {
    match s {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// `2026-06-01T09:00:00Z`.
pub fn iso_utc(t: i64) -> String {
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, (s / 60) % 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: i64, m: u32, d: u32, h: i64, mi: i64) -> i64 {
        days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60
    }

    #[test]
    fn hermes_schedule_forms() {
        let now = t(2026, 11, 2, 0, 0); // Monday 08:00 in UTC+8
        let s = parse("30m", now, 480).unwrap();
        assert_eq!((s.expr.as_str(), s.first_run, s.once), ("@every 30m", now + 1800, false));
        assert_eq!(parse("every 2h", now, 480).unwrap().expr, "@every 120m");
        assert_eq!(parse("every hour", now, 480).unwrap().expr, "@every 60m");
        let o = parse("in 30m", now, 480).unwrap();
        assert!(o.once && o.first_run == now + 1800 && o.expr.starts_with("@once 2026-11-02T00:30"));
        let w = parse("every monday 9am", now, 480).unwrap();
        assert_eq!(w.expr, "0 9 * * 1");
        assert_eq!(w.first_run, t(2026, 11, 2, 1, 0), "09:00 UTC+8 today");
        assert_eq!(parse("weekdays at 9:30pm", now, 480).unwrap().expr, "30 21 * * 1-5");
        assert_eq!(parse("every day at noon", now, 480).unwrap().expr, "0 12 * * *");
        assert_eq!(parse("every monday, wednesday and fri at 7", now, 0).unwrap().expr, "0 7 * * 1,3,5");
        assert_eq!(parse("0 9 * * *", now, 480).unwrap().first_run, t(2026, 11, 2, 1, 0));
        assert_eq!(parse("0 9 * * MON-FRI", now, 480).unwrap().expr, "0 9 * * MON-FRI");
        let iso = parse("2026-11-03T09:00:00", now, 480).unwrap();
        assert_eq!((iso.first_run, iso.once), (t(2026, 11, 3, 1, 0), true));
        assert_eq!(parse("2026-11-03T09:00:00Z", now, 480).unwrap().first_run, t(2026, 11, 3, 9, 0));
        assert_eq!(parse("2026-11-03 09:00+02:00", now, 480).unwrap().first_run, t(2026, 11, 3, 7, 0));
        // The stored one-shot expression round-trips and the scheduler cannot re-fire it.
        assert_eq!(parse(&iso.expr, now, 480).unwrap().first_run, iso.first_run);
        assert!(Cron::parse(&iso.expr).is_err());
        assert!(parse("2020-01-01T00:00:00", now, 0).unwrap_err().contains("past"));
        assert!(parse("every fortnight", now, 0).is_err());
        assert!(parse("in soon", now, 0).unwrap_err().contains("after 'in '"));
        assert!(parse("whenever", now, 0).unwrap_err().contains("Invalid schedule"));
        assert!(parse("2026-02-30T00:00", now, 0).is_err());
    }

    #[test]
    fn durations_clock_and_openclaw_shapes() {
        assert_eq!(parse_duration_minutes("1d").unwrap(), 1440);
        assert_eq!(parse_duration_minutes("hours").unwrap(), 60);
        assert!(parse_duration_minutes("5x").is_err());
        assert_eq!(parse_duration_ms("90s").unwrap(), 90_000);
        assert_eq!(parse_duration_ms("1h30m").unwrap(), 5_400_000);
        assert_eq!(parse_duration_ms("250").unwrap(), 250);
        assert!(parse_duration_ms("5 parsecs").is_err());
        assert_eq!(parse_clock("12am"), Some((0, 0)));
        assert_eq!(parse_clock("13pm"), None);
        assert_eq!(parse_clock("7:5"), None);
        let now = t(2026, 1, 1, 0, 0);
        let e = from_openclaw(&serde_json::json!({"kind":"every","everyMs": 300000}), now, 0).unwrap();
        assert_eq!((e.expr.as_str(), e.first_run), ("@every 5m", now + 300));
        assert!(from_openclaw(&serde_json::json!({"kind":"every","everyMs": 1000}), now, 0).is_err());
        let a = from_openclaw(&serde_json::json!({"kind":"at","at":"2026-01-02T00:00:00Z"}), now, 0).unwrap();
        assert!(a.once);
        let c = from_openclaw(&serde_json::json!({"kind":"cron","expr":"0 18 * * *","tz":"UTC+8"}), now, 0).unwrap();
        assert_eq!(c.first_run, t(2026, 1, 1, 10, 0));
        assert!(from_openclaw(&serde_json::json!({"kind":"stream"}), now, 0).is_err());
    }
}
