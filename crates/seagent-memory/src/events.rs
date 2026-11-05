//! Memory host SDK (OpenClaw packages/memory-host-sdk + src/memory-host-sdk, MIT): the durable
//! memory event store (`memory.recall.recorded`, `memory.promotion.applied`,
//! `memory.dream.completed`, plus `memory.write`), per-consumer cursors, and the JSON query API
//! (`host_call`) a memory provider plugin uses: search, get, events, status, dreaming status.

use crate::util::{self, clip};
use crate::Host;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_EVENTS: usize = 10_000;
const MAX_ITEMS: usize = 10;
const MAX_TEXT: usize = 2048;
const MAX_PATH: usize = 256;
pub const EVENT_TYPES: &[&str] = &["memory.recall.recorded", "memory.recall.skipped", "memory.promotion.applied", "memory.dream.completed", "memory.write"];

fn file(data: &Path) -> PathBuf {
    data.join("memory/events/events.jsonl")
}

/// Bound diagnostic detail before persistence (aggregate counts stay exact).
fn bound(mut v: Value) -> Value {
    let mut truncated = false;
    if let Some(o) = v.as_object_mut() {
        for (k, x) in o.iter_mut() {
            match x {
                Value::String(s) => {
                    let lim = if k.ends_with("Path") || k == "path" { MAX_PATH } else { MAX_TEXT };
                    if s.len() > lim {
                        *s = clip(s, lim);
                        truncated = true;
                    }
                }
                Value::Array(a) if a.len() > MAX_ITEMS => {
                    a.truncate(MAX_ITEMS);
                    truncated = true;
                }
                _ => {}
            }
        }
        if truncated {
            o.insert("storageTruncated".into(), json!(true));
        }
    }
    v
}

/// Append an event (`type` must be one of `EVENT_TYPES`); the log keeps the newest `MAX_EVENTS`.
pub fn record(data: &Path, kind: &str, mut payload: Value) -> Result<(), String> {
    if !EVENT_TYPES.contains(&kind) {
        return Err(format!("unknown memory event type `{kind}`"));
    }
    payload["type"] = json!(kind);
    payload["timestamp"] = json!(util::iso(util::now_ms()));
    let p = file(data);
    util::append_line(&p, &bound(payload).to_string())?;
    let n = fs::read_to_string(&p).map(|t| t.lines().count()).unwrap_or(0);
    if n > MAX_EVENTS + MAX_EVENTS / 10 {
        let t = fs::read_to_string(&p).unwrap_or_default();
        let keep: Vec<&str> = t.lines().skip(n - MAX_EVENTS).collect();
        util::write_atomic(&p, format!("{}\n", keep.join("\n")).as_bytes())?;
    }
    Ok(())
}

/// Events oldest first, filtered by type and `after` (sequence number = line index).
pub fn list(data: &Path, kinds: &[&str], after: Option<usize>, limit: usize) -> Vec<(usize, Value)> {
    let t = fs::read_to_string(file(data)).unwrap_or_default();
    t.lines()
        .enumerate()
        .filter(|(i, _)| after.is_none_or(|a| *i > a))
        .filter_map(|(i, l)| serde_json::from_str::<Value>(l).ok().map(|v| (i, v)))
        .filter(|(_, v)| kinds.is_empty() || kinds.iter().any(|k| v["type"] == *k))
        .take(limit)
        .collect()
}

fn cursor_file(data: &Path) -> PathBuf {
    data.join("memory/events/cursors.json")
}

/// Events a named consumer has not seen yet; advances its cursor.
pub fn consume(data: &Path, consumer: &str, kinds: &[&str], limit: usize) -> Result<Vec<Value>, String> {
    let mut cur = util::read_json(&cursor_file(data)).unwrap_or(json!({}));
    let after = cur[consumer].as_u64().map(|n| n as usize);
    let evs = list(data, kinds, after, limit);
    if let Some((last, _)) = evs.last() {
        cur[consumer] = json!(last);
        if let Some(o) = cur.as_object_mut() {
            while o.len() > 1000 {
                let k = o.keys().next().cloned().unwrap_or_default();
                o.remove(&k);
            }
        }
        util::write_json(&cursor_file(data), &cur)?;
    }
    Ok(evs.into_iter().map(|(_, v)| v).collect())
}

/// The query API (`seagent/memory.host.<method>` from plugins, or in-process callers).
pub fn host_call(host: &Host, method: &str, p: &Value) -> Result<Value, String> {
    let s = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("");
    match method {
        "search" => {
            let q = s("query");
            if q.trim().is_empty() {
                return Err("search needs `query`".into());
            }
            let max = p["maxResults"].as_u64().map(|n| n as usize).unwrap_or(host.settings.search.max_results);
            let min = p["minScore"].as_f64().unwrap_or(host.settings.search.min_score);
            let sources: Vec<&str> = match s("corpus") {
                "sessions" => vec!["sessions"],
                "memory" => vec!["memory"],
                _ => vec![],
            };
            let out = host.search(q, max, min, &sources)?;
            Ok(json!({"results": out.hits.iter().map(|h| json!({"path": h.path, "startLine": h.start_line, "endLine": h.end_line, "score": h.score, "snippet": h.snippet, "source": h.source, "citation": h.citation()})).collect::<Vec<_>>(), "provider": out.provider, "mode": out.mode}))
        }
        "get" => Ok(crate::tools::read_memory_file(host, s("path"), p["from"].as_u64().map(|n| n as usize), p["lines"].as_u64().map(|n| n as usize))),
        "events" => {
            let kinds: Vec<String> = p["types"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
            let kinds: Vec<&str> = kinds.iter().map(String::as_str).collect();
            let limit = p["limit"].as_u64().unwrap_or(100) as usize;
            let evs = match p["consumer"].as_str() {
                Some(c) => consume(&host.data, c, &kinds, limit)?,
                None => list(&host.data, &kinds, p["after"].as_u64().map(|n| n as usize), limit).into_iter().map(|(i, mut v)| {
                    v["seq"] = json!(i);
                    v
                }).collect(),
            };
            Ok(json!({"events": evs}))
        }
        "status" => Ok(host.status()),
        "dreaming.status" => Ok(crate::dreaming::status_json(host)),
        "record" => {
            record(&host.data, s("type"), p.get("payload").cloned().unwrap_or(json!({})))?;
            Ok(json!({"ok": true}))
        }
        other => Err(format!("unknown memory host method `{other}`; use search, get, events, status, dreaming.status or record")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_bounds_and_cursors() {
        let d = crate::tmp("events");
        record(&d, "memory.recall.recorded", json!({"query": "x".repeat(5000), "resultCount": 12, "results": (0..12).collect::<Vec<_>>()})).unwrap();
        record(&d, "memory.dream.completed", json!({"phase": "light"})).unwrap();
        assert!(record(&d, "bogus", json!({})).is_err());
        let all = list(&d, &[], None, 10);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].1["results"].as_array().unwrap().len(), MAX_ITEMS);
        assert_eq!(all[0].1["resultCount"], 12, "aggregate counts stay exact");
        assert_eq!(all[0].1["storageTruncated"], true);
        assert_eq!(list(&d, &["memory.dream.completed"], None, 10).len(), 1);
        assert_eq!(consume(&d, "wiki", &[], 10).unwrap().len(), 2);
        assert!(consume(&d, "wiki", &[], 10).unwrap().is_empty());
        record(&d, "memory.write", json!({"action": "add"})).unwrap();
        assert_eq!(consume(&d, "wiki", &[], 10).unwrap()[0]["type"], "memory.write");
    }
}
