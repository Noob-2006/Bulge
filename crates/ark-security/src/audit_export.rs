//! SIEM forwarding of the audit stream (ent-074 syslog, ent-075 Splunk HEC, ent-076 OTLP logs).
//!
//! ```toml
//! [audit.export.syslog]
//! address = "udp://siem.corp:514"     # udp://, tcp:// (RFC 6587 octet counting) or unix:///dev/log
//! app_name = "ark"
//! facility = 13                       # log audit
//!
//! [audit.export.splunk_hec]
//! url = "https://splunk.corp:8088"    # /services/collector/event is appended
//! token = "{{secret:SPLUNK_HEC}}"
//! index = "security"
//! sourcetype = "ark:audit"
//!
//! [audit.export.otlp]
//! endpoint = "http://otel-collector:4318"   # /v1/logs is appended
//! headers = { "x-api-key" = "{{secret:OTLP_KEY}}" }
//! ```
//!
//! Each sink keeps its own cursor (`<data>/audit/export/<sink>.cursor` = last seq delivered),
//! so delivery is at-least-once across restarts and a SIEM outage only delays, never drops,
//! records (until retention prunes them). Records travel with their `seq`, `prev` and `hash`:
//! the SIEM copy is the external anchor `ark audit verify --anchor` checks against.

use crate::audit;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExportConfig {
    pub syslog: Option<SyslogConfig>,
    pub splunk_hec: Option<HecConfig>,
    pub otlp: Option<OtlpConfig>,
    /// Records per sink per pump (default 500).
    pub batch: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyslogConfig {
    pub address: String,
    pub app_name: String,
    pub facility: u8,
    pub hostname: String,
}
impl Default for SyslogConfig {
    fn default() -> Self {
        SyslogConfig { address: String::new(), app_name: "ark".into(), facility: 13, hostname: String::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HecConfig {
    pub url: String,
    pub token: String,
    pub index: String,
    pub sourcetype: String,
    pub source: String,
}
impl Default for HecConfig {
    fn default() -> Self {
        HecConfig { url: String::new(), token: String::new(), index: String::new(), sourcetype: "ark:audit".into(), source: "ark".into() }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub headers: BTreeMap<String, String>,
    pub service_name: String,
}

impl ExportConfig {
    pub fn sinks(&self) -> Vec<&'static str> {
        let mut v = vec![];
        if self.syslog.as_ref().is_some_and(|s| !s.address.trim().is_empty()) {
            v.push("syslog");
        }
        if self.splunk_hec.as_ref().is_some_and(|s| !s.url.trim().is_empty()) {
            v.push("splunk_hec");
        }
        if self.otlp.as_ref().is_some_and(|s| !s.endpoint.trim().is_empty()) {
            v.push("otlp");
        }
        v
    }
}

fn cursor_path(data: &Path, sink: &str) -> PathBuf {
    audit::dir(data).join("export").join(format!("{sink}.cursor"))
}

pub fn cursor(data: &Path, sink: &str) -> u64 {
    std::fs::read_to_string(cursor_path(data, sink)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

fn set_cursor(data: &Path, sink: &str, seq: u64) {
    let p = cursor_path(data, sink);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(p, seq.to_string());
}

/// RFC 3339 UTC with milliseconds, from Unix ms (no date crate).
pub fn rfc3339(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, ms % 1000)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "-".into())
}

fn severity(r: &Value) -> u8 {
    match r["outcome"].as_str().unwrap_or("") {
        o if o.starts_with("deny") || o == "error" || o == "fail" => 4, // warning
        _ => 5,                                                          // notice
    }
}

fn sd_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace(']', "\\]")
}

/// One RFC 5424 line: structured data carries the chain fields, the message is the record.
pub fn rfc5424(r: &Value, c: &SyslogConfig) -> String {
    let pri = c.facility as u32 * 8 + severity(r) as u32;
    let host = if c.hostname.is_empty() { hostname() } else { c.hostname.clone() };
    let msgid: String = r["kind"].as_str().unwrap_or("-").chars().filter(|c| c.is_ascii_graphic()).take(32).collect();
    let sd = format!(
        "[ark@32473 seq=\"{}\" hash=\"{}\" kind=\"{}\" actor=\"{}\" outcome=\"{}\"]",
        r["seq"].as_u64().unwrap_or(0),
        sd_escape(r["hash"].as_str().unwrap_or("")),
        sd_escape(r["kind"].as_str().unwrap_or("")),
        sd_escape(&format!("{}:{}", r["actor"]["kind"].as_str().unwrap_or(""), r["actor"]["name"].as_str().unwrap_or(""))),
        sd_escape(r["outcome"].as_str().unwrap_or("")),
    );
    format!("<{pri}>1 {} {host} {} {} {} {sd} {}", rfc3339(r["ts"].as_u64().unwrap_or(0)), if c.app_name.is_empty() { "ark" } else { &c.app_name }, std::process::id(), if msgid.is_empty() { "-".into() } else { msgid }, audit::canonical(r))
}

fn send_syslog(c: &SyslogConfig, recs: &[Value]) -> Result<(), String> {
    let addr = c.address.trim();
    if let Some(hp) = addr.strip_prefix("udp://") {
        let sock = std::net::UdpSocket::bind(if hp.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" }).map_err(|e| e.to_string())?;
        for r in recs {
            sock.send_to(rfc5424(r, c).as_bytes(), hp).map_err(|e| format!("syslog {hp}: {e}"))?;
        }
        Ok(())
    } else if let Some(hp) = addr.strip_prefix("tcp://") {
        use std::net::ToSocketAddrs;
        let sa = hp.to_socket_addrs().map_err(|e| format!("syslog {hp}: {e}"))?.next().ok_or("syslog: no address")?;
        let mut s = std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(10)).map_err(|e| format!("syslog {hp}: {e}"))?;
        let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
        for r in recs {
            let m = rfc5424(r, c);
            // RFC 6587 octet counting: `<len> <msg>`.
            write!(s, "{} {m}", m.len()).map_err(|e| format!("syslog {hp}: {e}"))?;
        }
        s.flush().map_err(|e| e.to_string())
    } else if let Some(p) = addr.strip_prefix("unix://") {
        let sock = std::os::unix::net::UnixDatagram::unbound().map_err(|e| e.to_string())?;
        for r in recs {
            sock.send_to(rfc5424(r, c).as_bytes(), p).map_err(|e| format!("syslog {p}: {e}"))?;
        }
        Ok(())
    } else {
        Err(format!("syslog address `{addr}`: use udp://host:port, tcp://host:port or unix:///dev/log"))
    }
}

fn agent() -> ureq::Agent {
    ark_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(20))).build().into()
}

/// Splunk HEC batch body: one event object per record, concatenated.
pub fn hec_body(c: &HecConfig, recs: &[Value]) -> String {
    let host = hostname();
    recs.iter()
        .map(|r| {
            let mut e = json!({"time": r["ts"].as_u64().unwrap_or(0) as f64 / 1000.0, "host": host, "source": c.source, "sourcetype": c.sourcetype, "event": r});
            if !c.index.is_empty() {
                e["index"] = c.index.clone().into();
            }
            e.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn send_hec(c: &HecConfig, recs: &[Value], resolve: &dyn Fn(&str) -> String) -> Result<(), String> {
    let base = c.url.trim().trim_end_matches('/');
    let url = if base.ends_with("/services/collector/event") || base.ends_with("/services/collector") { base.to_string() } else { format!("{base}/services/collector/event") };
    let token = resolve(&c.token);
    if token.is_empty() || token.contains("{{secret:") {
        return Err("splunk_hec: token is not set (or its secret does not resolve)".into());
    }
    let resp = agent().post(&url).header("Authorization", &format!("Splunk {token}")).header("Content-Type", "application/json").send(hec_body(c, recs)).map_err(|e| format!("splunk_hec: {e}"))?;
    let st = resp.status().as_u16();
    if (200..300).contains(&st) {
        Ok(())
    } else {
        Err(format!("splunk_hec: HTTP {st}"))
    }
}

/// OTLP/HTTP JSON `ExportLogsServiceRequest`.
pub fn otlp_body(c: &OtlpConfig, recs: &[Value]) -> Value {
    let kv = |k: &str, v: Value| json!({"key": k, "value": v});
    let s = |x: &str| json!({"stringValue": x});
    let records: Vec<Value> = recs
        .iter()
        .map(|r| {
            let sev = severity(r);
            json!({
                "timeUnixNano": (r["ts"].as_u64().unwrap_or(0) as u128 * 1_000_000).to_string(),
                "severityNumber": if sev == 4 { 13 } else { 10 },
                "severityText": if sev == 4 { "WARN" } else { "INFO" },
                "body": s(&audit::canonical(r)),
                "attributes": [
                    kv("event.name", s(&format!("ark.audit.{}", r["kind"].as_str().unwrap_or("")))),
                    kv("ark.audit.seq", json!({"intValue": r["seq"].as_u64().unwrap_or(0).to_string()})),
                    kv("ark.audit.hash", s(r["hash"].as_str().unwrap_or(""))),
                    kv("ark.audit.outcome", s(r["outcome"].as_str().unwrap_or(""))),
                    kv("enduser.id", s(r["actor"]["name"].as_str().unwrap_or(""))),
                    kv("ark.audit.actor_kind", s(r["actor"]["kind"].as_str().unwrap_or(""))),
                ],
            })
        })
        .collect();
    let svc = if c.service_name.is_empty() { "ark" } else { &c.service_name };
    json!({"resourceLogs": [{
        "resource": {"attributes": [kv("service.name", s(svc)), kv("host.name", s(&hostname()))]},
        "scopeLogs": [{"scope": {"name": "ark.audit", "version": "1"}, "logRecords": records}],
    }]})
}

fn send_otlp(c: &OtlpConfig, recs: &[Value], resolve: &dyn Fn(&str) -> String) -> Result<(), String> {
    let base = c.endpoint.trim().trim_end_matches('/');
    let url = if base.ends_with("/v1/logs") { base.to_string() } else { format!("{base}/v1/logs") };
    let mut req = agent().post(&url).header("Content-Type", "application/json");
    for (k, v) in &c.headers {
        let v = resolve(v);
        if v.contains("{{secret:") {
            return Err(format!("otlp: header `{k}` uses a secret that does not resolve"));
        }
        req = req.header(k.as_str(), &v);
    }
    let resp = req.send(otlp_body(c, recs).to_string()).map_err(|e| format!("otlp: {e}"))?;
    let st = resp.status().as_u16();
    if (200..300).contains(&st) {
        Ok(())
    } else {
        Err(format!("otlp: HTTP {st}"))
    }
}

/// Deliver everything each sink has not seen yet. Returns `(sink, Ok(records sent) | Err)`.
pub fn pump(data: &Path, c: &ExportConfig, resolve: &dyn Fn(&str) -> String) -> Vec<(&'static str, Result<usize, String>)> {
    let sinks = c.sinks();
    if sinks.is_empty() {
        return vec![];
    }
    let all = audit::all(data);
    let batch = if c.batch == 0 { 500 } else { c.batch };
    let mut out = vec![];
    for sink in sinks {
        let from = cursor(data, sink);
        let todo: Vec<Value> = all.iter().filter(|r| r["seq"].as_u64().unwrap_or(0) > from).take(batch).cloned().collect();
        if todo.is_empty() {
            out.push((sink, Ok(0)));
            continue;
        }
        let res = match sink {
            "syslog" => send_syslog(c.syslog.as_ref().unwrap(), &todo),
            "splunk_hec" => send_hec(c.splunk_hec.as_ref().unwrap(), &todo, resolve),
            _ => send_otlp(c.otlp.as_ref().unwrap(), &todo, resolve),
        };
        match res {
            Ok(()) => {
                set_cursor(data, sink, todo.last().and_then(|r| r["seq"].as_u64()).unwrap_or(from));
                out.push((sink, Ok(todo.len())));
            }
            Err(e) => out.push((sink, Err(e))),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{emit, Actor, Event};
    use std::io::{BufRead, BufReader, Read};
    use std::net::{TcpListener, UdpSocket};

    struct G(PathBuf);
    impl Drop for G {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(tag: &str) -> G {
        let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let d = base.join(format!("ark-auditx-{tag}-{}-{}", std::process::id(), audit::now_ms()));
        std::fs::create_dir_all(&d).unwrap();
        G(d)
    }
    fn seed(d: &Path, n: usize) {
        for i in 0..n {
            emit(d, Event::new("app.request", Actor::new("token", "bot"), &format!("m{i}"), if i == 0 { "deny" } else { "allow" })).unwrap();
        }
    }

    /// A one-shot HTTP server: returns (url, receiver of (request head, body)).
    fn fake_http(status: u16) -> (String, std::sync::mpsc::Receiver<(String, String)>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    head.push_str(&line);
                }
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 {status} X\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}");
                let _ = tx.send((head, String::from_utf8_lossy(&body).to_string()));
            }
        });
        (url, rx)
    }

    #[test]
    fn rfc3339_and_rfc5424_shape() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_709_210_096_789), "2024-02-29T12:34:56.789Z");
        let r = json!({"seq": 7, "ts": 0, "kind": "auth.denied", "outcome": "deny", "hash": "ab", "actor": {"kind": "token", "name": "x\"y"}});
        let line = rfc5424(&r, &SyslogConfig { hostname: "h".into(), ..Default::default() });
        assert!(line.starts_with("<108>1 1970-01-01T00:00:00.000Z h ark "), "{line}"); // 13*8+4
        assert!(line.contains("auth.denied [ark@32473 seq=\"7\" hash=\"ab\""), "{line}");
        assert!(line.contains("actor=\"token:x\\\"y\""), "{line}");
    }

    #[test]
    fn syslog_udp_and_tcp_deliver_and_advance_cursor() {
        let g = tmp("syslog");
        seed(&g.0, 3);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let c = ExportConfig { syslog: Some(SyslogConfig { address: format!("udp://{}", udp.local_addr().unwrap()), ..Default::default() }), ..Default::default() };
        let r = pump(&g.0, &c, &|s| s.to_string());
        assert_eq!(r[0].1, Ok(3));
        let mut buf = [0u8; 4096];
        let n = udp.recv(&mut buf).unwrap();
        let first = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(first.starts_with("<108>1 ") && first.contains("seq=\"1\""), "{first}");
        assert_eq!(cursor(&g.0, "syslog"), 3);
        assert_eq!(pump(&g.0, &c, &|s| s.to_string())[0].1, Ok(0), "nothing resent");

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut all = String::new();
            s.read_to_string(&mut all).unwrap();
            all
        });
        let g2 = tmp("syslogtcp");
        seed(&g2.0, 2);
        let c = ExportConfig { syslog: Some(SyslogConfig { address: format!("tcp://{addr}"), ..Default::default() }), ..Default::default() };
        assert_eq!(pump(&g2.0, &c, &|s| s.to_string())[0].1, Ok(2));
        let got = h.join().unwrap();
        let (len, rest) = got.split_once(' ').unwrap();
        assert!(rest.len() > len.parse::<usize>().unwrap(), "two framed messages");
    }

    #[test]
    fn splunk_hec_posts_events_with_token_and_keeps_cursor_on_failure() {
        let g = tmp("hec");
        seed(&g.0, 2);
        let (url, rx) = fake_http(200);
        let c = ExportConfig { splunk_hec: Some(HecConfig { url, token: "{{secret:HEC}}".into(), index: "sec".into(), ..Default::default() }), ..Default::default() };
        let resolve = |s: &str| s.replace("{{secret:HEC}}", "fake-hec-token");
        assert_eq!(pump(&g.0, &c, &resolve)[0].1, Ok(2));
        let (head, body) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("POST /services/collector/event"), "{head}");
        assert!(head.to_ascii_lowercase().contains("authorization: splunk fake-hec-token"));
        let first: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(first["index"], "sec");
        assert_eq!(first["event"]["seq"], 1);
        // A failing collector leaves the cursor where it was.
        emit(&g.0, Event::new("x", Actor::system(), "y", "ok")).unwrap();
        let (url, _rx) = fake_http(503);
        let c = ExportConfig { splunk_hec: Some(HecConfig { url, token: "t".into(), ..Default::default() }), ..Default::default() };
        assert!(pump(&g.0, &c, &|s| s.to_string())[0].1.is_err());
        assert_eq!(cursor(&g.0, "splunk_hec"), 2);
        // Unresolved secret is refused before sending.
        let c = ExportConfig { splunk_hec: Some(HecConfig { url: "http://127.0.0.1:9".into(), token: "{{secret:NOPE}}".into(), ..Default::default() }), ..Default::default() };
        assert!(pump(&g.0, &c, &|s| s.to_string())[0].1.as_ref().unwrap_err().contains("token"));
    }

    #[test]
    fn otlp_logs_carry_audit_records() {
        let g = tmp("otlp");
        seed(&g.0, 1);
        let (url, rx) = fake_http(200);
        let c = ExportConfig { otlp: Some(OtlpConfig { endpoint: url, headers: [("x-api-key".to_string(), "k".to_string())].into(), ..Default::default() }), ..Default::default() };
        assert_eq!(pump(&g.0, &c, &|s| s.to_string())[0].1, Ok(1));
        let (head, body) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("POST /v1/logs") && head.to_ascii_lowercase().contains("x-api-key: k"));
        let v: Value = serde_json::from_str(&body).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "WARN");
        assert!(rec["body"]["stringValue"].as_str().unwrap().contains("\"seq\":1"));
    }
}
