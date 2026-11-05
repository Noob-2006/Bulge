//! Cron expressions (5 fields, names, ranges, steps, macros) plus `@every 15m`.
//! Evaluated in a fixed UTC offset (no DST surprises; Taiwan has none).

use crate::util::{civil_from_days, days_from_civil};

#[derive(Debug, Clone, PartialEq)]
pub enum Cron {
    Fields { min: u64, hour: u32, dom: u32, month: u16, dow: u8, dom_star: bool, dow_star: bool },
    Every(i64),
}

fn parse_field(s: &str, lo: u32, hi: u32, names: &[&str]) -> Result<(u64, bool), String> {
    let mut bits = 0u64;
    let star = s == "*" || s.starts_with("*/");
    for part in s.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, st)) => (r, st.parse::<u32>().map_err(|_| format!("bad step `{st}`"))?),
            None => (part, 1),
        };
        if step == 0 {
            return Err("step must be > 0".into());
        }
        let val = |v: &str| -> Result<u32, String> {
            let lv = v.to_ascii_lowercase();
            if let Some(i) = names.iter().position(|n| *n == lv) {
                return Ok(i as u32 + lo);
            }
            v.parse::<u32>().map_err(|_| format!("bad value `{v}`"))
        };
        let (a, b) = if range == "*" {
            (lo, hi)
        } else if let Some((x, y)) = range.split_once('-') {
            (val(x)?, val(y)?)
        } else {
            let v = val(range)?;
            (v, if part.contains('/') { hi } else { v })
        };
        if a < lo || b > hi || a > b {
            return Err(format!("`{part}` out of range {lo}-{hi}"));
        }
        let mut v = a;
        while v <= b {
            bits |= 1 << v;
            v += step;
        }
    }
    Ok((bits, star))
}

impl Cron {
    pub fn parse(expr: &str) -> Result<Cron, String> {
        let e = expr.trim();
        let e = match e {
            "@hourly" => "0 * * * *",
            "@daily" | "@midnight" => "0 0 * * *",
            "@weekly" => "0 0 * * 0",
            "@monthly" => "0 0 1 * *",
            "@yearly" | "@annually" => "0 0 1 1 *",
            _ => e,
        };
        if let Some(rest) = e.strip_prefix("@every") {
            let r = rest.trim();
            let (num, unit) = r.split_at(r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len()));
            let n: i64 = num.parse().map_err(|_| format!("bad interval `{r}`"))?;
            let mult = match unit {
                "s" => 1,
                "m" | "" => 60,
                "h" => 3600,
                "d" => 86_400,
                _ => return Err(format!("bad unit `{unit}` (s/m/h/d)")),
            };
            if n <= 0 || n * mult < 60 {
                return Err("interval must be at least 60s".into());
            }
            return Ok(Cron::Every(n * mult));
        }
        let f: Vec<&str> = e.split_whitespace().collect();
        if f.len() != 5 {
            return Err(format!("expected 5 fields, got {}", f.len()));
        }
        const MON: &[&str] = &["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
        const DOW: &[&str] = &["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
        let (min, _) = parse_field(f[0], 0, 59, &[])?;
        let (hour, _) = parse_field(f[1], 0, 23, &[])?;
        let (dom, dom_star) = parse_field(f[2], 1, 31, &[])?;
        let (month, _) = parse_field(f[3], 1, 12, MON)?;
        let (mut dow, dow_star) = parse_field(f[4], 0, 7, DOW)?;
        if dow & (1 << 7) != 0 {
            dow |= 1; // 7 == Sunday
        }
        Ok(Cron::Fields { min, hour: hour as u32, dom: dom as u32, month: month as u16, dow: (dow & 0x7f) as u8, dom_star, dow_star })
    }

    /// First fire time strictly after `after` (unix secs), in UTC+offset.
    pub fn next_after(&self, after: i64, offset_min: i32) -> Option<i64> {
        match self {
            Cron::Every(n) => Some(after - after.rem_euclid(*n) + n),
            Cron::Fields { min, hour, dom, month, dow, dom_star, dow_star } => {
                let off = offset_min as i64 * 60;
                let local = after + off;
                let mut day = local.div_euclid(86_400);
                let mut start_min = (local.rem_euclid(86_400) / 60) + 1;
                #[allow(clippy::explicit_counter_loop)]
                for _ in 0..(366 * 5) {
                    let (y, m, d) = civil_from_days(day);
                    let wd = (day + 4).rem_euclid(7) as u32; // 1970-01-01 was Thursday
                    let dom_ok = dom & (1 << d) != 0;
                    let dow_ok = dow & (1 << wd) != 0;
                    let day_ok = if *dom_star || *dow_star { dom_ok && dow_ok } else { dom_ok || dow_ok };
                    if month & (1 << m) != 0 && day_ok {
                        for mm in start_min..1440 {
                            if hour & (1 << (mm / 60)) != 0 && min & (1 << (mm % 60)) != 0 {
                                return Some(days_from_civil(y, m, d) * 86_400 + mm * 60 - off);
                            }
                        }
                    }
                    day += 1;
                    start_min = 0;
                }
                None // e.g. 31 Feb
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: i64, m: u32, d: u32, h: i64, mi: i64) -> i64 {
        days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60
    }

    #[test]
    fn basic_and_offsets() {
        let c = Cron::parse("30 9 * * *").unwrap();
        // 09:30 in UTC+8 is 01:30 UTC.
        assert_eq!(c.next_after(t(2026, 11, 1, 0, 0), 480), Some(t(2026, 11, 1, 1, 30)));
        assert_eq!(c.next_after(t(2026, 11, 1, 1, 30), 480), Some(t(2026, 11, 2, 1, 30)), "strictly after");
        assert_eq!(c.next_after(t(2026, 11, 1, 0, 0), 0), Some(t(2026, 11, 1, 9, 30)));
    }

    #[test]
    fn steps_lists_names_and_weekday_rules() {
        let c = Cron::parse("*/15 8-10 * * mon-fri").unwrap();
        // 2026-11-01 is a Sunday → next is Monday 08:00.
        assert_eq!(c.next_after(t(2026, 11, 1, 12, 0), 0), Some(t(2026, 11, 2, 8, 0)));
        assert_eq!(c.next_after(t(2026, 11, 2, 8, 0), 0), Some(t(2026, 11, 2, 8, 15)));
        let sun7 = Cron::parse("0 0 * * 7").unwrap();
        assert_eq!(sun7.next_after(t(2026, 11, 1, 1, 0), 0), Some(t(2026, 11, 8, 0, 0)));
        // dom and dow both restricted → OR.
        let or = Cron::parse("0 0 13 * fri").unwrap();
        assert_eq!(or.next_after(t(2026, 11, 1, 0, 0), 0), Some(t(2026, 11, 6, 0, 0)));
        let lst = Cron::parse("0 0 1,15 jan,jul *").unwrap();
        assert_eq!(lst.next_after(t(2026, 11, 1, 0, 0), 0), Some(t(2027, 1, 1, 0, 0)));
        assert_eq!(Cron::parse("@daily").unwrap(), Cron::parse("0 0 * * *").unwrap());
        // Leap day.
        assert_eq!(Cron::parse("0 0 29 2 *").unwrap().next_after(t(2026, 3, 1, 0, 0), 0), Some(t(2028, 2, 29, 0, 0)));
    }

    #[test]
    fn every_interval() {
        let c = Cron::parse("@every 15m").unwrap();
        assert_eq!(c.next_after(t(2026, 1, 1, 0, 7), 0), Some(t(2026, 1, 1, 0, 15)));
        assert_eq!(Cron::parse("@every 2h").unwrap(), Cron::Every(7200));
    }

    #[test]
    fn invalid_expressions() {
        for bad in ["", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "*/0 * * * *", "5-1 * * * *", "x * * * *", "@every", "@every 10s", "@every 5x", "@every -5m", "* * * foo *"] {
            assert!(Cron::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(Cron::parse("0 0 31 2 *").unwrap().next_after(0, 0), None, "impossible date");
    }
}
