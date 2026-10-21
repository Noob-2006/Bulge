//! Saved-task scheduling: one-shot and recurring schedules, plus the JSON
//! store beside the other bulge state files.
//!
//! All times are Unix seconds (UTC). Wall-clock selectors (`daily`, `weekly`
//! and cron) are interpreted in a fixed UTC offset supplied by the caller, so
//! this module needs no time-zone database. The tick loop that launches the
//! agent lives outside this crate; this is pure time math and persistence.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The schedule file name, joined to `~/.bulge` by the caller.
pub const SCHEDULE_FILE: &str = "schedule.json";

const SECONDS_PER_DAY: i64 = 86_400;
const MINUTE_SECONDS: u64 = 60;
/// Bound the minute-by-minute search for wall-clock schedules.
const SCAN_LIMIT_MINUTES: u64 = 366 * 24 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Weekday {
    /// Monday = 0 through Sunday = 6.
    fn index(self) -> u8 {
        match self {
            Self::Mon => 0,
            Self::Tue => 1,
            Self::Wed => 2,
            Self::Thu => 3,
            Self::Fri => 4,
            Self::Sat => 5,
            Self::Sun => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Schedule {
    /// One-shot, `seconds` after it was created (needs a base time to resolve).
    AfterSeconds { seconds: u64 },
    /// One-shot at an absolute Unix time.
    At { unix: u64 },
    /// Recurring every `seconds` (at least 60 when built through [`Schedule::every`]).
    EverySeconds { seconds: u64 },
    /// Daily at hour:minute in the supplied offset.
    Daily { hour: u8, minute: u8 },
    /// Weekly on `weekdays` at hour:minute in the supplied offset.
    Weekly {
        weekdays: Vec<Weekday>,
        hour: u8,
        minute: u8,
    },
    /// 5-field Vixie cron expression `"min hour dom mon dow"`.
    Cron { expr: String },
    /// Event-driven: fire whenever a watched filesystem path changes. This has no
    /// time-based next occurrence (so [`next_occurrence`] returns `None`); the
    /// scheduler decides it is due by comparing the path's mtime to what it last
    /// saw. Recurring (never a one-shot).
    OnPathChange { path: String },
}

impl Schedule {
    /// A recurring schedule with a 60-second floor.
    pub fn every(seconds: u64) -> Self {
        Self::EverySeconds {
            seconds: seconds.max(60),
        }
    }

    /// True for one-shot schedules: they fire once, then are disabled.
    pub fn is_one_shot(&self) -> bool {
        matches!(self, Self::AfterSeconds { .. } | Self::At { .. })
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJob {
    pub id: String,
    pub title: String,
    /// The task text handed to the agent when it fires.
    pub prompt: String,
    pub schedule: Schedule,
    /// Fixed UTC offset in minutes for wall-clock selectors (daily/weekly/cron).
    #[serde(default)]
    pub offset_minutes: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Scheduler-owned runtime state (kept with the job for simplicity).
    #[serde(default)]
    pub next_run_at: Option<u64>,
    #[serde(default)]
    pub last_run_at: Option<u64>,
    #[serde(default)]
    pub runs: u32,
}

/// Howard Hinnant's `days_from_civil`: days since 1970-01-01 for a Gregorian
/// date. `m` and `d` are one-based.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let m = i64::from(m);
    let d = i64::from(d);
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Howard Hinnant's `civil_from_days`: the inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m as u32, d as u32)
}

/// Weekday for a day number relative to 1970-01-01 (a Thursday): Mon = 0.
fn weekday_from_days(days: i64) -> u8 {
    (days + 3).rem_euclid(7) as u8
}

#[derive(Debug, Clone, Copy)]
struct WallClock {
    year: i64,
    month: u32,
    day: u32,
    hour: u8,
    minute: u8,
    second: u8,
    weekday: u8,
}

/// Split an instant into its wall-clock parts in a fixed UTC offset.
fn split_unix(second: u64, offset_minutes: i32) -> WallClock {
    let local = i128::from(second) + i128::from(offset_minutes) * 60;
    let days = local.div_euclid(i128::from(SECONDS_PER_DAY));
    let secs_of_day = local.rem_euclid(i128::from(SECONDS_PER_DAY));
    let (year, month, day) = civil_from_days(days as i64);
    let wall = WallClock {
        year,
        month,
        day,
        hour: (secs_of_day / 3_600) as u8,
        minute: (secs_of_day % 3_600 / 60) as u8,
        second: (secs_of_day % 60) as u8,
        weekday: weekday_from_days(days as i64),
    };
    debug_assert_eq!(
        days_from_civil(wall.year, wall.month, wall.day),
        days as i64
    );
    debug_assert_eq!(i128::from(wall.second), secs_of_day % 60);
    debug_assert_eq!(
        wall_clock_to_unix(&wall, offset_minutes),
        i128::from(second / MINUTE_SECONDS * MINUTE_SECONDS)
    );
    wall
}

/// Turn a wall-clock minute in a fixed offset back into a Unix second.
fn wall_clock_to_unix(wall: &WallClock, offset_minutes: i32) -> i128 {
    let days = i128::from(days_from_civil(wall.year, wall.month, wall.day));
    days * i128::from(SECONDS_PER_DAY)
        + i128::from(wall.hour) * 3_600
        + i128::from(wall.minute) * 60
        - i128::from(offset_minutes) * 60
}

/// The first minute boundary strictly after `after` (in seconds).
fn next_minute_start(after: u64) -> Option<u64> {
    (after / MINUTE_SECONDS)
        .checked_add(1)?
        .checked_mul(MINUTE_SECONDS)
}

/// Scan minute boundaries strictly after `after`, returning the first match.
fn scan_minutes<F>(after: u64, offset_minutes: i32, mut matches: F) -> Option<u64>
where
    F: FnMut(&WallClock) -> bool,
{
    let start = next_minute_start(after)?;
    for step in 0..=SCAN_LIMIT_MINUTES {
        let candidate = start.checked_add(step.checked_mul(MINUTE_SECONDS)?)?;
        if matches(&split_unix(candidate, offset_minutes)) {
            return Some(candidate);
        }
    }
    None
}

/// The next fire time strictly after `after` (Unix seconds). `base` anchors
/// relative schedules; it is only used by [`Schedule::AfterSeconds`] and
/// [`Schedule::EverySeconds`].
///
/// Returns `None` when a one-shot is already past, a cron expression is
/// invalid, or a wall-clock schedule matches nothing within ~366 days.
pub fn next_occurrence(
    sched: &Schedule,
    after: u64,
    base: u64,
    offset_minutes: i32,
) -> Option<u64> {
    match sched {
        Schedule::AfterSeconds { seconds } => {
            let at = base.checked_add(*seconds)?;
            (at > after).then_some(at)
        }
        Schedule::At { unix } => (*unix > after).then_some(*unix),
        Schedule::EverySeconds { seconds } => {
            let step = *seconds;
            if step == 0 {
                return None;
            }
            // Step from the anchor with k >= 1, so the result is always strictly
            // after `after` even when the anchor itself lies in the future.
            let k = if base > after {
                1
            } else {
                ((after - base) / step).checked_add(1)?
            };
            base.checked_add(k.checked_mul(step)?)
        }
        Schedule::Daily { hour, minute } => {
            if *hour > 23 || *minute > 59 {
                return None;
            }
            scan_minutes(after, offset_minutes, |wall| {
                wall.hour == *hour && wall.minute == *minute
            })
        }
        Schedule::Weekly {
            weekdays,
            hour,
            minute,
        } => {
            if weekdays.is_empty() || *hour > 23 || *minute > 59 {
                return None;
            }
            scan_minutes(after, offset_minutes, |wall| {
                wall.hour == *hour
                    && wall.minute == *minute
                    && weekdays.iter().any(|day| day.index() == wall.weekday)
            })
        }
        Schedule::Cron { expr } => {
            let spec = CronSpec::parse(expr)?;
            scan_minutes(after, offset_minutes, |wall| spec.matches(wall))
        }
        // Event-driven: no time-based occurrence; the scheduler polls the path.
        Schedule::OnPathChange { .. } => None,
    }
}

/// A parsed 5-field Vixie cron expression.
#[derive(Debug, Clone)]
struct CronSpec {
    minutes: [bool; 60],
    hours: [bool; 24],
    /// Indexed by day of month (1..=31; slot 0 is unused).
    days_of_month: [bool; 32],
    /// Indexed by month (1..=12; slot 0 is unused).
    months: [bool; 13],
    /// Indexed by weekday (Mon = 0 .. Sun = 6).
    days_of_week: [bool; 7],
    dom_restricted: bool,
    dow_restricted: bool,
}

impl CronSpec {
    fn parse(expr: &str) -> Option<Self> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return None;
        }

        let mut spec = Self {
            minutes: [false; 60],
            hours: [false; 24],
            days_of_month: [false; 32],
            months: [false; 13],
            days_of_week: [false; 7],
            dom_restricted: fields[2] != "*",
            dow_restricted: fields[4] != "*",
        };

        for value in expand_field(fields[0], 0, 59)? {
            spec.minutes[value as usize] = true;
        }
        for value in expand_field(fields[1], 0, 23)? {
            spec.hours[value as usize] = true;
        }
        for value in expand_field(fields[2], 1, 31)? {
            spec.days_of_month[value as usize] = true;
        }
        for value in expand_field(fields[3], 1, 12)? {
            spec.months[value as usize] = true;
        }
        for value in expand_field(fields[4], 0, 7)? {
            spec.days_of_week[cron_dow_index(value)?] = true;
        }

        Some(spec)
    }

    fn matches(&self, wall: &WallClock) -> bool {
        if !self.minutes[usize::from(wall.minute)]
            || !self.hours[usize::from(wall.hour)]
            || !self.months[wall.month as usize]
        {
            return false;
        }

        let dom = self.days_of_month[wall.day as usize];
        let dow = self.days_of_week[usize::from(wall.weekday)];
        match (self.dom_restricted, self.dow_restricted) {
            // Standard Vixie behavior: when both are restricted, either may match.
            (true, true) => dom || dow,
            (true, false) => dom,
            (false, true) => dow,
            (false, false) => true,
        }
    }
}

/// Vixie cron numbers weekdays 0 = Sunday, 1 = Monday .. 6 = Saturday, with 7
/// also accepted as Sunday. Convert to this module's Mon = 0 representation.
fn cron_dow_index(value: u32) -> Option<usize> {
    match value {
        0 | 7 => Some(6),
        1 => Some(0),
        2 => Some(1),
        3 => Some(2),
        4 => Some(3),
        5 => Some(4),
        6 => Some(5),
        _ => None,
    }
}

/// Expand one cron field into the numeric values it selects.
fn expand_field(field: &str, min: u32, max: u32) -> Option<Vec<u32>> {
    if field.is_empty() {
        return None;
    }

    let mut values = Vec::new();
    for part in field.split(',') {
        if part.is_empty() {
            return None;
        }

        let (base, step) = match part.split_once('/') {
            Some((base, step)) => (base, step.parse::<u32>().ok()?),
            None => (part, 1),
        };
        if step == 0 {
            return None;
        }

        let (low, high) = if base == "*" {
            (min, max)
        } else if let Some((low, high)) = base.split_once('-') {
            (low.parse::<u32>().ok()?, high.parse::<u32>().ok()?)
        } else {
            let value = base.parse::<u32>().ok()?;
            (value, value)
        };

        if low < min || high > max || low > high {
            return None;
        }

        let mut value = low;
        loop {
            values.push(value);
            match value.checked_add(step) {
                Some(next) if next <= high => value = next,
                _ => break,
            }
        }
    }

    Some(values)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleStore {
    #[serde(default)]
    pub jobs: Vec<ScheduledJob>,
}

impl ScheduleStore {
    /// Load the schedule at `path`. A missing file is an empty store; a
    /// malformed one is an error, so a corrupt schedule is never overwritten.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(source) => serde_json::from_str(&source)
                .map_err(|error| format!("parse {}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("read {}: {error}", path.display())),
        }
    }

    /// Save atomically: write a sibling temp file, then rename it over `path`.
    /// Creates the parent directory when needed.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let source = serde_json::to_string_pretty(self)
            .map_err(|error| format!("serialize schedule: {error}"))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let file = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(SCHEDULE_FILE);
        let temp = path.with_file_name(format!("{file}.tmp-{}", std::process::id()));
        std::fs::write(&temp, source)
            .map_err(|error| format!("write {}: {error}", temp.display()))?;
        std::fs::rename(&temp, path).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            format!("rename {} to {}: {error}", temp.display(), path.display())
        })
    }

    pub fn get(&self, id: &str) -> Option<&ScheduledJob> {
        self.jobs.iter().find(|job| job.id == id)
    }

    /// Replace the job with the same id, or append it.
    pub fn upsert(&mut self, job: ScheduledJob) {
        match self.jobs.iter_mut().find(|existing| existing.id == job.id) {
            Some(existing) => *existing = job,
            None => self.jobs.push(job),
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        match self.jobs.iter().position(|job| job.id == id) {
            Some(index) => {
                self.jobs.remove(index);
                true
            }
            None => false,
        }
    }

    /// Enabled jobs whose `next_run_at` has arrived.
    pub fn due(&self, now: u64) -> Vec<ScheduledJob> {
        self.jobs
            .iter()
            .filter(|job| job.enabled && job.next_run_at.is_some_and(|at| at <= now))
            .cloned()
            .collect()
    }

    /// Record that a job fired at `now`. One-shots are disabled; recurring jobs
    /// advance to the next occurrence strictly after `now`, coalescing missed
    /// runs instead of backfilling them.
    pub fn mark_fired(&mut self, id: &str, now: u64) {
        let Some(job) = self.jobs.iter_mut().find(|job| job.id == id) else {
            return;
        };
        job.runs = job.runs.saturating_add(1);
        job.last_run_at = Some(now);
        if job.schedule.is_one_shot() {
            job.enabled = false;
            job.next_run_at = None;
        } else {
            job.next_run_at = next_occurrence(&job.schedule, now, now, job.offset_minutes);
        }
    }

    /// (Re)compute `next_run_at` from `now` using the job's schedule.
    pub fn schedule_next(&mut self, id: &str, now: u64) {
        let Some(job) = self.jobs.iter_mut().find(|job| job.id == id) else {
            return;
        };
        job.next_run_at = next_occurrence(&job.schedule, now, now, job.offset_minutes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn job(id: &str, schedule: Schedule) -> ScheduledJob {
        ScheduledJob {
            id: id.to_owned(),
            title: format!("Job {id}"),
            prompt: format!("Do {id}"),
            schedule,
            offset_minutes: 0,
            enabled: true,
            next_run_at: None,
            last_run_at: None,
            runs: 0,
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bulge-cron-{}-{label}", std::process::id()))
    }

    #[test]
    fn civil_days_round_trip_and_match_known_epochs() {
        let dates = [
            (1970, 1, 1),
            (2000, 2, 29),
            (2024, 2, 29),
            (2026, 10, 21),
            (1969, 12, 31),
            (1900, 3, 1),
            (2100, 12, 31),
        ];
        for (year, month, day) in dates {
            let days = days_from_civil(year, month, day);
            assert_eq!(civil_from_days(days), (year, month, day));
        }

        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(days_from_civil(2026, 10, 21), 20_747);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn weekdays_use_monday_zero() {
        assert_eq!(
            weekday_from_days(days_from_civil(1970, 1, 1)),
            3,
            "Thursday"
        );
        assert_eq!(
            weekday_from_days(days_from_civil(2026, 10, 21)),
            2,
            "Wednesday"
        );
        assert_eq!(
            weekday_from_days(days_from_civil(2026, 10, 26)),
            0,
            "Monday"
        );
        assert_eq!(Weekday::Sun.index(), 6);

        let wall = split_unix(0, 0);
        assert_eq!(wall.year, 1970);
        assert_eq!(wall.month, 1);
        assert_eq!(wall.day, 1);
        assert_eq!(wall.weekday, 3);
    }

    #[test]
    fn wall_clock_to_unix_inverts_split() {
        let wall = split_unix(1_792_540_800, 480);
        assert_eq!(wall.year, 2026);
        assert_eq!(wall.month, 10);
        assert_eq!(wall.day, 21);
        assert_eq!(wall.hour, 8);
        assert_eq!(wall.minute, 0);
        assert_eq!(wall.second, 0);
        assert_eq!(wall_clock_to_unix(&wall, 480), 1_792_540_800);
    }

    #[test]
    fn one_shot_semantics_and_every_floor() {
        assert_eq!(Schedule::every(10), Schedule::EverySeconds { seconds: 60 });
        assert_eq!(Schedule::every(0), Schedule::EverySeconds { seconds: 60 });
        assert_eq!(
            Schedule::every(300),
            Schedule::EverySeconds { seconds: 300 }
        );

        assert!(Schedule::AfterSeconds { seconds: 5 }.is_one_shot());
        assert!(Schedule::At { unix: 100 }.is_one_shot());
        assert!(!Schedule::every(60).is_one_shot());
        assert!(!Schedule::Daily { hour: 1, minute: 2 }.is_one_shot());

        assert_eq!(
            next_occurrence(&Schedule::At { unix: 100 }, 100, 0, 0),
            None,
            "a one-shot at exactly `after` is already past"
        );
        assert_eq!(
            next_occurrence(&Schedule::At { unix: 101 }, 100, 0, 0),
            Some(101)
        );
        assert_eq!(
            next_occurrence(&Schedule::AfterSeconds { seconds: 30 }, 100, 90, 0),
            Some(120)
        );
        assert_eq!(
            next_occurrence(&Schedule::AfterSeconds { seconds: 30 }, 120, 90, 0),
            None
        );
    }

    #[test]
    fn every_seconds_steps_strictly_forward_from_the_anchor() {
        let schedule = Schedule::every(300);
        assert_eq!(next_occurrence(&schedule, 100, 100, 0), Some(400));
        assert_eq!(next_occurrence(&schedule, 400, 100, 0), Some(700));
        assert_eq!(next_occurrence(&schedule, 1_000, 100, 0), Some(1_300));
        assert_eq!(next_occurrence(&schedule, 1_300, 100, 0), Some(1_600));
    }

    #[test]
    fn daily_crosses_local_midnight_with_a_fixed_offset() {
        // 2026-10-21 23:50 in UTC+8 == 2026-10-21 15:50 UTC.
        let after = 1_792_597_800;
        let schedule = Schedule::Daily { hour: 0, minute: 5 };
        // 2026-10-22 00:05 in UTC+8 == 2026-10-21 16:05 UTC.
        assert_eq!(
            next_occurrence(&schedule, after, 0, 480),
            Some(1_792_598_700)
        );

        // Daily at 09:00 in UTC+8 after 08:00 local is the same local day.
        let schedule = Schedule::Daily { hour: 9, minute: 0 };
        // 2026-10-21 08:00 in UTC+8 == 2026-10-21 00:00 UTC.
        assert_eq!(
            next_occurrence(&schedule, 1_792_540_800, 0, 480),
            Some(1_792_544_400)
        );
    }

    #[test]
    fn weekly_only_matches_listed_weekdays() {
        let schedule = Schedule::Weekly {
            weekdays: vec![Weekday::Mon, Weekday::Wed],
            hour: 9,
            minute: 0,
        };

        // Wednesday 2026-10-21 10:00 UTC: Wednesday's slot has passed.
        assert_eq!(
            next_occurrence(&schedule, 1_792_576_800, 0, 0),
            Some(1_793_005_200)
        );
        // Monday 2026-10-26 08:00 UTC: the same day's 09:00 slot is next.
        assert_eq!(
            next_occurrence(&schedule, 1_793_001_600, 0, 0),
            Some(1_793_005_200)
        );
    }

    #[test]
    fn cron_weekdays_fire_monday_to_friday() {
        let schedule = Schedule::Cron {
            expr: "0 9 * * 1-5".to_owned(),
        };
        // Saturday 2026-10-24 12:00 UTC -> Monday 2026-10-26 09:00 UTC.
        assert_eq!(
            next_occurrence(&schedule, 1_792_843_200, 0, 0),
            Some(1_793_005_200)
        );

        // Sunday is also selectable as 0 or 7 in Vixie cron.
        let sunday = Schedule::Cron {
            expr: "0 9 * * 7".to_owned(),
        };
        assert_eq!(
            next_occurrence(&sunday, 1_792_843_200, 0, 0),
            Some(1_792_918_800)
        );
    }

    #[test]
    fn cron_restricted_dom_and_dow_match_either() {
        // The 13th OR a Friday, at midnight UTC.
        let schedule = Schedule::Cron {
            expr: "0 0 13 * 5".to_owned(),
        };
        // After Friday 2026-10-09 00:00 UTC, the 13th (Tuesday) matches next.
        assert_eq!(
            next_occurrence(&schedule, 1_791_504_000, 0, 0),
            Some(1_791_849_600)
        );
    }

    #[test]
    fn cron_step_and_invalid_expressions() {
        let schedule = Schedule::Cron {
            expr: "*/15 * * * *".to_owned(),
        };
        // 2026-10-21 09:07:30 UTC -> 09:15:00 UTC.
        assert_eq!(
            next_occurrence(&schedule, 1_792_573_650, 0, 0),
            Some(1_792_574_100)
        );

        let invalid = Schedule::Cron {
            expr: "not a cron".to_owned(),
        };
        assert_eq!(next_occurrence(&invalid, 0, 0, 0), None);
        let out_of_range = Schedule::Cron {
            expr: "0 99 * * *".to_owned(),
        };
        assert_eq!(next_occurrence(&out_of_range, 0, 0, 0), None);
    }

    #[test]
    fn store_upsert_get_and_remove() {
        let mut store = ScheduleStore::default();
        store.upsert(job("a", Schedule::every(60)));
        store.upsert(job("b", Schedule::At { unix: 500 }));
        assert_eq!(store.jobs.len(), 2);
        assert_eq!(
            store.get("a").map(|entry| entry.title.as_str()),
            Some("Job a")
        );
        assert!(store.get("missing").is_none());

        store.upsert(job("a", Schedule::At { unix: 100 }));
        assert_eq!(store.jobs.len(), 2, "upsert replaces by id");
        assert_eq!(
            store.get("a").map(|entry| entry.schedule.clone()),
            Some(Schedule::At { unix: 100 })
        );

        assert!(store.remove("a"));
        assert!(!store.remove("a"));
        assert_eq!(store.jobs.len(), 1);
    }

    #[test]
    fn schedule_next_makes_jobs_due_when_their_time_arrives() {
        let mut store = ScheduleStore::default();
        let mut one_shot = job("once", Schedule::At { unix: 1_000 });
        one_shot.enabled = true;
        store.upsert(one_shot);
        store.upsert(job("later", Schedule::AfterSeconds { seconds: 60 }));
        store.upsert(job("off", Schedule::At { unix: 1_000 }));
        if let Some(off) = store.jobs.iter_mut().find(|entry| entry.id == "off") {
            off.enabled = false;
        }

        store.schedule_next("once", 0);
        store.schedule_next("later", 500);
        store.schedule_next("off", 0);
        assert_eq!(
            store.get("once").and_then(|entry| entry.next_run_at),
            Some(1_000)
        );
        assert_eq!(
            store.get("later").and_then(|entry| entry.next_run_at),
            Some(560)
        );

        assert!(store.due(559).is_empty());
        let due = store.due(560);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "later");
        assert_eq!(store.due(1_000).len(), 2);
    }

    #[test]
    fn mark_fired_disables_one_shot_and_advances_recurring() {
        let mut store = ScheduleStore::default();
        store.upsert(job("once", Schedule::At { unix: 1_000 }));
        store.schedule_next("once", 0);
        store.mark_fired("once", 1_000);
        let one_shot = store.get("once").expect("job exists");
        assert!(!one_shot.enabled);
        assert_eq!(one_shot.next_run_at, None);
        assert_eq!(one_shot.last_run_at, Some(1_000));
        assert_eq!(one_shot.runs, 1);

        let mut recurring = job("every", Schedule::every(300));
        recurring.next_run_at = Some(1_000);
        store.upsert(recurring);
        // Fired late at 1_400: coalesce to 1_700 rather than backfilling 1_300.
        store.mark_fired("every", 1_400);
        let recurring = store.get("every").expect("job exists");
        assert!(recurring.enabled);
        assert_eq!(recurring.next_run_at, Some(1_700));
        assert_eq!(recurring.last_run_at, Some(1_400));
        assert_eq!(recurring.runs, 1);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = temp_dir("round-trip");
        let path = dir.join(SCHEDULE_FILE);
        let _ = std::fs::remove_dir_all(&dir);

        let mut store = ScheduleStore::default();
        store.upsert(job(
            "daily",
            Schedule::Daily {
                hour: 9,
                minute: 30,
            },
        ));
        store.upsert(job(
            "weekly",
            Schedule::Weekly {
                weekdays: vec![Weekday::Mon, Weekday::Fri],
                hour: 18,
                minute: 0,
            },
        ));
        store.upsert(job(
            "cron",
            Schedule::Cron {
                expr: "*/15 * * * *".to_owned(),
            },
        ));
        store.save(&path).expect("saves");

        let loaded = ScheduleStore::load(&path).expect("loads");
        assert_eq!(loaded, store);
        assert_eq!(
            loaded.get("weekly").expect("job exists").schedule,
            Schedule::Weekly {
                weekdays: vec![Weekday::Mon, Weekday::Fri],
                hour: 18,
                minute: 0,
            }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_schedule_loads_as_empty() {
        let dir = temp_dir("missing");
        let path = dir.join(SCHEDULE_FILE);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            ScheduleStore::load(&path).expect("missing is empty"),
            ScheduleStore::default()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
