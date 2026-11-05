//! `/queue debounce <duration|off>` (OpenClaw `/queue` `debounce` argument, `reply/queue/directive.ts`):
//! hold the run of a channel session for a quiet period so a burst of messages is answered in
//! one turn. The first message of a burst schedules the delayed run; later ones only queue.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
struct St {
    ms: HashMap<String, u64>,
    pending: HashSet<String>,
}
static ST: Mutex<Option<St>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut St) -> R) -> R {
    let mut g = ST.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(St::default))
}

/// Upstream `parseQueueDebounce`: `500ms`, `2s`, `1m`; a bare number is milliseconds.
pub fn parse(raw: &str) -> Result<u64, String> {
    let s = raw.trim().to_ascii_lowercase();
    if matches!(s.as_str(), "off" | "0" | "none") {
        return Ok(0);
    }
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }
    let (num, mul) = if let Some(n) = s.strip_suffix("ms") { (n, 1.0) } else if let Some(n) = s.strip_suffix('s') { (n, 1000.0) } else if let Some(n) = s.strip_suffix('m') { (n, 60_000.0) } else { return Err(format!("invalid debounce: {raw} (e.g. 500ms, 2s)")) };
    let v: f64 = num.trim().parse().map_err(|_| format!("invalid debounce: {raw} (e.g. 500ms, 2s)"))?;
    if v < 0.0 {
        return Err("debounce must not be negative".into());
    }
    Ok((v * mul) as u64)
}

pub fn set(session: &str, ms: u64) {
    with(|s| if ms == 0 { s.ms.remove(session); } else { s.ms.insert(session.to_string(), ms); });
}
pub fn get(session: &str) -> u64 {
    with(|s| s.ms.get(session).copied().unwrap_or(0))
}

pub enum Gate {
    /// No debounce: run now.
    Now,
    /// First message of a burst: run after this delay (then call [`done`]).
    Delay(Duration),
    /// A delayed run is already scheduled.
    Skip,
}

pub fn gate(session: &str) -> Gate {
    with(|s| match s.ms.get(session).copied() {
        None | Some(0) => Gate::Now,
        Some(ms) if s.pending.insert(session.to_string()) => Gate::Delay(Duration::from_millis(ms)),
        Some(_) => Gate::Skip,
    })
}

pub fn done(session: &str) {
    with(|s| s.pending.remove(session));
}

/// The `/queue debounce …` sub-command.
pub fn command(session: &str, arg: Option<&str>) -> Result<String, String> {
    let Some(a) = arg else { return Ok(format!("debounce: {}", match get(session) { 0 => "off".to_string(), ms => format!("{ms}ms") })) };
    let ms = parse(a)?;
    set(session, ms);
    Ok(if ms == 0 { "debounce off".into() } else { format!("debounce {ms}ms: a burst of messages is answered in one turn") })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_gate_bursts() {
        assert_eq!(parse("500ms").unwrap(), 500);
        assert_eq!(parse("2s").unwrap(), 2000);
        assert_eq!(parse("1m").unwrap(), 60_000);
        assert_eq!(parse("750").unwrap(), 750);
        assert!(parse("soon").is_err());
        assert!(matches!(gate("s-db"), Gate::Now));
        assert_eq!(command("s-db", Some("2s")).unwrap(), "debounce 2000ms: a burst of messages is answered in one turn");
        assert!(matches!(gate("s-db"), Gate::Delay(d) if d == Duration::from_secs(2)));
        assert!(matches!(gate("s-db"), Gate::Skip), "burst: one delayed run");
        done("s-db");
        assert!(matches!(gate("s-db"), Gate::Delay(_)));
        assert_eq!(command("s-db", Some("off")).unwrap(), "debounce off");
        assert!(matches!(gate("s-db"), Gate::Now));
    }
}
