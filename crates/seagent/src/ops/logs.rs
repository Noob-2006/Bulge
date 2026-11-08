//! Logs (OpenClaw `logs` + file logging, Hermes `logs`): the daemon writes structured
//! JSONL records to `<data>/logs/seagent.jsonl` (rotated at `MAX_BYTES`, `KEEP` files) from a
//! kernel tap; `seagent daemon start` also keeps its stderr in `<data>/seagentd.log`.
//! `seagent logs` merges both with filters (`--level`, `--since`, `--grep`, `--session`,
//! `-n`, `--follow`, `--json`); a running daemon serves the same through `logs.tail`.

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;
use seagent_kernel::event::{Event, EventKind};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const COMMANDS: &[&str] = &["logs", "log"];
pub const VALUE_FLAGS: &[&str] = &["level", "since", "grep"];
pub const BOOL_FLAGS: &[&str] = &[];

pub const MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const KEEP: usize = 5;

pub fn dir(paths: &Paths) -> PathBuf {
    paths.log_dir()
}

fn level_rank(l: &str) -> u8 {
    match l {
        "error" => 4,
        "warn" | "warning" => 3,
        "info" => 2,
        _ => 1,
    }
}

/// One record per interesting event (None = not logged).
pub fn record(session: &str, e: &Event) -> Option<Value> {
    let (level, kind, msg) = match &e.kind {
        EventKind::Notice { level, text } => (if level == "warn" { "warn" } else { "info" }.to_string(), "notice", text.clone()),
        EventKind::Error { message } => ("error".into(), "error", message.clone()),
        EventKind::TurnStart { turn } => ("info".into(), "turn_start", format!("turn {turn} started")),
        EventKind::TurnEnd { reason, usage, .. } => (if reason == "done" || reason == "idle" { "info" } else { "warn" }.into(), "turn_end", format!("turn ended: {reason} · {} tokens", usage.total())),
        EventKind::ToolCalled { name, .. } => ("debug".into(), "tool", format!("tool {name}")),
        EventKind::ToolSettled { is_error: true, tool_use_id, .. } => ("warn".into(), "tool_error", format!("tool call {tool_use_id} failed")),
        EventKind::Gate { gate, verdict, reason, .. } => ("warn".into(), "gate", format!("{gate} gate: {verdict} — {reason}")),
        EventKind::Model { model } => ("info".into(), "model", format!("model → {model}")),
        EventKind::Compaction { tokens_before, .. } => ("info".into(), "compaction", format!("compacted ({tokens_before} tokens before)")),
        _ => return None,
    };
    Some(json!({"ts": e.ts, "level": level, "session": session, "kind": kind, "msg": msg}))
}

pub struct Writer {
    dir: PathBuf,
    max: u64,
    keep: usize,
    f: Mutex<Option<std::fs::File>>,
}

impl Writer {
    pub fn new(dir: PathBuf, max: u64, keep: usize) -> Writer {
        Writer { dir, max, keep, f: Mutex::new(None) }
    }
    fn path(&self) -> PathBuf {
        self.dir.join("seagent.jsonl")
    }
    pub fn write(&self, v: &Value) {
        let mut g = self.f.lock().unwrap();
        let p = self.path();
        if std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0) >= self.max {
            *g = None;
            for i in (1..self.keep).rev() {
                let _ = std::fs::rename(self.dir.join(format!("seagent.{i}.jsonl")), self.dir.join(format!("seagent.{}.jsonl", i + 1)));
            }
            let _ = std::fs::rename(&p, self.dir.join("seagent.1.jsonl"));
            let _ = std::fs::remove_file(self.dir.join(format!("seagent.{}.jsonl", self.keep)));
        }
        if g.is_none() {
            let _ = std::fs::create_dir_all(&self.dir);
            *g = std::fs::OpenOptions::new().create(true).append(true).open(&p).ok();
            let _ = crate::ops::hostos::set_mode(&p, 0o600);
        }
        if let Some(f) = g.as_mut() {
            let _ = writeln!(f, "{v}");
        }
    }
}

/// Install the logging tap on the daemon's kernel.
pub fn install(k: &seagent_kernel::kernel::Kernel) {
    let w = Arc::new(Writer::new(dir(&k.paths), MAX_BYTES, KEEP));
    w.write(&json!({"ts": seagent_kernel::event::now_ms(), "level": "info", "session": "", "kind": "daemon", "msg": format!("seagentd {} started (pid {})", env!("CARGO_PKG_VERSION"), std::process::id())}));
    let vault = k.vault.clone();
    k.add_tap(Arc::new(move |sid: &str, e: &Event| {
        if let Some(mut r) = record(sid, e) {
            r["msg"] = json!(vault.redact(r["msg"].as_str().unwrap_or("")));
            w.write(&r);
        }
    }));
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub level: Option<String>,
    pub since_ms: Option<u64>,
    pub grep: Option<String>,
    pub session: Option<String>,
}

/// `10m`, `2h`, `3d`, `45s` or unix seconds → absolute ms.
pub fn parse_since(s: &str, now_ms: u64) -> Option<u64> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().ok()?;
    let secs = match unit {
        "" if n > 1_000_000_000 => return Some(n * 1000),
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return None,
    };
    Some(now_ms.saturating_sub(secs * 1000))
}

fn seagentd_line(l: &str, mtime_ms: u64) -> Value {
    let lower = l.to_lowercase();
    let level = if lower.contains("error") || lower.contains("failed") || lower.contains("panic") { "error" } else if lower.contains("warning") || lower.contains("stopped") { "warn" } else { "info" };
    json!({"ts": mtime_ms, "level": level, "session": "", "kind": "seagentd", "msg": l})
}

/// Records from the JSONL files (oldest first) and the daemon's stderr log.
pub fn read(paths: &Paths, f: &Filter, limit: usize) -> Vec<Value> {
    let d = dir(paths);
    let mut files: Vec<PathBuf> = (1..=KEEP).rev().map(|i| d.join(format!("seagent.{i}.jsonl"))).collect();
    files.push(d.join("seagent.jsonl"));
    let mut out: Vec<Value> = files.iter().filter_map(|p| std::fs::read_to_string(p).ok()).flat_map(|t| t.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).collect::<Vec<_>>()).collect();
    let stderr = paths.daemon_log();
    if let Ok(t) = std::fs::read_to_string(&stderr) {
        let m = std::fs::metadata(&stderr).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
        out.extend(t.lines().rev().take(2000).collect::<Vec<_>>().into_iter().rev().map(|l| seagentd_line(l, m)));
        out.sort_by_key(|v| v["ts"].as_u64().unwrap_or(0));
    }
    let min = f.level.as_deref().map(level_rank).unwrap_or(0);
    let g = f.grep.as_ref().map(|g| g.to_lowercase());
    let kept: Vec<Value> = out
        .into_iter()
        .filter(|v| level_rank(v["level"].as_str().unwrap_or("")) >= min)
        .filter(|v| f.since_ms.is_none_or(|s| v["ts"].as_u64().unwrap_or(0) >= s))
        .filter(|v| f.session.as_ref().is_none_or(|s| v["session"].as_str().is_some_and(|x| x.starts_with(s.as_str()))))
        .filter(|v| g.as_ref().is_none_or(|g| v["msg"].as_str().unwrap_or("").to_lowercase().contains(g.as_str())))
        .collect();
    let skip = kept.len().saturating_sub(limit);
    kept[skip..].to_vec()
}

pub fn format(v: &Value) -> String {
    format!("{} {:<5} {}{}", seagent_kernel::util::fmt_time((v["ts"].as_u64().unwrap_or(0) / 1000) as i64, 480), v["level"].as_str().unwrap_or(""), v["session"].as_str().filter(|s| !s.is_empty()).map(|s| format!("[{}] ", &s[..s.len().min(12)])).unwrap_or_default(), v["msg"].as_str().unwrap_or(""))
}

/// `logs.tail {lines, level, grep, session, since}` on the daemon.
pub fn methods(paths: Paths) -> seagent_kernel::daemon::MethodExt {
    Arc::new(move |m: &str, p: &Value| {
        (m == "logs.tail").then(|| {
            let f = Filter { level: p["level"].as_str().map(String::from), since_ms: p["since"].as_str().and_then(|s| parse_since(s, seagent_kernel::event::now_ms())), grep: p["grep"].as_str().map(String::from), session: p["session"].as_str().map(String::from) };
            Ok(json!(read(&paths, &f, p["lines"].as_u64().unwrap_or(200).min(5000) as usize)))
        })
    })
}

fn filter(a: &Args) -> Filter {
    Filter { level: a.val("level").map(String::from), since_ms: a.val("since").and_then(|s| parse_since(s, seagent_kernel::event::now_ms())), grep: a.val("grep").map(String::from), session: a.val("session").map(String::from) }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    COMMANDS.contains(&cmd).then(|| show(a))
}

pub fn show(a: &Args) -> R {
    (|| -> R {
        let paths = Paths::from_env();
        let n = a.num::<usize>("lines").map_err(crate::Fail::Usage)?.or(a.num::<usize>("limit").map_err(crate::Fail::Usage)?).unwrap_or(100);
        let f = filter(a);
        let print = |v: &Value| if a.flag("json") { println!("{v}") } else { println!("{}", format(v)) };
        let recs = read(&paths, &f, n);
        if recs.is_empty() && !a.flag("follow") {
            println!("no log records yet ({} — the daemon writes them while it runs)", dir(&paths).display());
        }
        let mut last = recs.last().and_then(|v| v["ts"].as_u64()).unwrap_or(0);
        let mut seen = recs.len();
        for v in &recs {
            print(v);
        }
        if a.flag("follow") {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let all = read(&paths, &Filter { since_ms: Some(last), ..f.clone() }, 10_000);
                let fresh: Vec<&Value> = all.iter().filter(|v| v["ts"].as_u64().unwrap_or(0) > last || (v["ts"].as_u64() == Some(last) && seen == 0)).collect();
                for v in &fresh {
                    print(v);
                }
                if let Some(t) = fresh.last().and_then(|v| v["ts"].as_u64()) {
                    last = t;
                    seen = 1;
                }
            }
        }
        Ok(0)
    })()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_rotates_and_filters() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-logs-{}", seagent_kernel::util::random_hex(4)));
        let paths = Paths { data: root.join("data"), config_dir: root.join("c"), runtime: root.join("r"), ..Default::default() };
        let w = Writer::new(dir(&paths), 300, 3);
        for i in 0..20u64 {
            let e = Event { seq: i, ts: 1_000_000 + i * 1000, kind: if i % 5 == 0 { EventKind::Error { message: format!("boom {i}") } } else { EventKind::Notice { level: "info".into(), text: format!("note {i}") } } };
            w.write(&record(if i < 10 { "sessA" } else { "sessB" }, &e).unwrap());
        }
        assert!(dir(&paths).join("seagent.1.jsonl").exists() && !dir(&paths).join("seagent.4.jsonl").exists(), "rotated, capped at 3 files");
        let errs = read(&paths, &Filter { level: Some("error".into()), ..Default::default() }, 100);
        assert!(errs.iter().all(|v| v["level"] == "error") && !errs.is_empty());
        let b = read(&paths, &Filter { session: Some("sessB".into()), grep: Some("NOTE 1".into()), ..Default::default() }, 100);
        assert!(b.iter().all(|v| v["session"] == "sessB" && v["msg"].as_str().unwrap().starts_with("note 1")));
        assert_eq!(read(&paths, &Filter::default(), 2).len(), 2);
        assert_eq!(parse_since("10m", 1_000_000), Some(400_000));
        assert_eq!(parse_since("1700000000", 0), Some(1_700_000_000_000));
        assert!(parse_since("5y", 0).is_none());
        std::fs::write(paths.daemon_log(), "seagentd: channel tg: reply failed: x\n").unwrap();
        assert!(read(&paths, &Filter { level: Some("error".into()), ..Default::default() }, 100).iter().any(|v| v["kind"] == "seagentd"));
        let m = methods(paths.clone());
        assert!(m("logs.tail", &json!({"lines": 3})).unwrap().unwrap().as_array().unwrap().len() == 3);
        assert!(record("s", &Event { seq: 0, ts: 0, kind: EventKind::Title { title: "x".into() } }).is_none());
    }
}
