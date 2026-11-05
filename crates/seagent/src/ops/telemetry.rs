//! `seagent telemetry` — the operator surface of gateway monitoring (Hermes `hermes monitoring
//! status`, `hermes_cli/subcommands/monitoring.py` + `agent/monitoring/*`).
//!
//! The exporter itself lives in [`crate::agentcmds::monitoring`]: a bounded queue of
//! content-free events (`gateway_health`, `gateway_diagnostic`, `cron_execution`) drained by one
//! thread into OTel spans over OTLP/HTTP JSON, with `{{secret:NAME}}` headers resolved at send
//! time. This module adds what the daemon cannot answer on its own:
//!
//! * `seagent telemetry status [--json]` — the export posture: which signals are on, the collector
//!   endpoint (`/v1/traces` is appended), the resolved service name and pseudonymous install id,
//!   which headers are configured (names only — values never leave the process), whether an
//!   exporter is attached in *this* process and the redaction promise. Mirrors upstream
//!   `hermes monitoring status`, including the "always on" content-safety line and the scope
//!   footer.
//! * `seagent telemetry test [--endpoint URL] [--json]` — send one probe span (`telemetry.test`,
//!   gateway_health, no prompt data) through the same exporter the daemon uses and report the
//!   collector's HTTP status. `--endpoint` overrides `[telemetry] endpoint` for a one-off check;
//!   it never edits the config.
//!
//! Exit codes: 0 on success, 1 when the collector answers non-2xx or is unreachable, 2 for a
//! usage error (unknown action, `[telemetry] enabled = false` without `--allow-disabled`).

use crate::args::Args;
use crate::R;
use seagent_kernel::config::{Paths, TelemetryConfig};
use serde_json::{json, Value};

pub const COMMANDS: &[&str] = &["telemetry"];
pub const VALUE_FLAGS: &[&str] = &["endpoint"];
pub const BOOL_FLAGS: &[&str] = &["allow-disabled"];

/// One probe span: a gateway_health event with no session, message or tool data.
pub fn probe_event() -> Value {
    json!({"event": "gateway_health", "name": "telemetry.test", "gateway_state": "running",
           "new_state": "running", "version": env!("CARGO_PKG_VERSION"), "pid": std::process::id()})
}

/// Header names only: an operator sees *which* headers are sent, never their values
/// (those may be API keys, often through `{{secret:NAME}}`).
pub fn header_names(t: &TelemetryConfig) -> Vec<String> {
    t.headers.keys().cloned().collect()
}

/// The `/v1/traces` URL an export would POST to.
pub fn url(t: &TelemetryConfig, endpoint: Option<&str>) -> String {
    crate::agentcmds::monitoring::traces_endpoint(endpoint.map(str::to_string).unwrap_or_else(|| t.endpoint.clone()).as_str())
}

/// `seagent telemetry status`: upstream's `monitoring status` layout, seagent's config keys.
pub fn status_text(t: &TelemetryConfig, data: &std::path::Path, attached: Option<&Value>) -> String {
    let on = |b: bool| if b { "on" } else { "off" };
    let mut s = String::from("Gateway monitoring\n");
    s.push_str(&format!("  Health export:  {} ([telemetry] enabled)\n", if t.enabled { "enabled" } else { "disabled" }));
    s.push_str(&format!("    Traces:       {} (sample {:.2}) → {}\n", on(t.traces), t.sample_ratio, url(t, None)));
    s.push_str(&format!("    Metrics:      {} → /v1/metrics\n", on(t.metrics)));
    s.push_str(&format!("    Logs:         {} → /v1/logs\n", on(t.logs)));
    s.push_str(&format!("    Flush every:  {}s\n", t.flush_secs));
    s.push_str(&format!("  OTLP endpoint:  {}\n", if t.endpoint.trim().is_empty() { "(not configured)".to_string() } else { t.endpoint.clone() }));
    let h = header_names(t);
    s.push_str(&format!("  Headers:        {}\n", if h.is_empty() { "none".to_string() } else { format!("{} ({}) — values hidden, {{{{secret:NAME}}}} resolved at send time", h.len(), h.join(", ")) }));
    s.push_str(&format!("  Service name:   {}\n", t.service_name));
    s.push_str(&format!("  Install id:     {}\n", crate::agentcmds::monitoring::install_id(data)));
    s.push_str("  Redaction:      always on (prompts, messages, tool args and session ids are never exported)\n");
    match attached {
        Some(_) => s.push_str("  Exporter:       attached in this process\n"),
        None => s.push_str("  Exporter:       not attached here (only the daemon exports; `seagent telemetry test` checks reachability)\n"),
    }
    if let Some(src) = seagent_net::http::offline_source() {
        s.push_str(&format!("  Offline:        on ({src}) — nothing is exported\n"));
    }
    s.push_str("\n  Scope: gateway service health + redacted diagnostics only.\n");
    if !t.enabled {
        s.push_str("  Enable with: `seagent config set telemetry.enabled true` (then restart the daemon).\n");
    }
    s
}

/// The same facts as [`status_text`], for the Control UI / scripts.
pub fn status_json(t: &TelemetryConfig, data: &std::path::Path, attached: Option<&Value>) -> Value {
    json!({
        "enabled": t.enabled,
        "endpoint": t.endpoint,
        "traces_url": url(t, None),
        "service_name": t.service_name,
        "sample_ratio": t.sample_ratio,
        "flush_secs": t.flush_secs,
        "signals": {"traces": t.traces, "metrics": t.metrics, "logs": t.logs},
        "headers": header_names(t),
        "install_id": crate::agentcmds::monitoring::install_id(data),
        "scope": "gateway_monitoring",
        "redaction": "always on",
        "exporter": attached.cloned(),
    })
}

/// POST one probe span with the daemon's exporter. Returns `(url, http status, spans)`.
pub fn probe(k: &seagent_kernel::kernel::Kernel, endpoint: Option<&str>) -> Result<(String, u16, usize), String> {
    let batch = [probe_event()];
    let mut o = crate::agentcmds::monitoring::Otlp::new(k);
    if let Some(ep) = endpoint {
        o.url = url(&k.cfg.telemetry, Some(ep));
    }
    let url = o.url.clone();
    let code = o.export(&batch)?;
    Ok((url, code, batch.len()))
}

fn build(a: &Args) -> Result<(seagent_kernel::config::Config, Paths), crate::Fail> {
    let paths = Paths::from_env();
    let ws = crate::workspace(a)?;
    let cfg = crate::load_config(a, &ws, &paths)?;
    Ok((cfg, paths))
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "telemetry" {
        return None;
    }
    Some((|| -> R {
        match a.pos(0).unwrap_or("status") {
            "status" => {
                let (cfg, paths) = build(a)?;
                let attached = crate::agentcmds::monitoring::status();
                let attached = attached.get("exporter").filter(|v| !v.is_null()).cloned();
                if a.flag("json") {
                    println!("{}", status_json(&cfg.telemetry, &paths.data, attached.as_ref()));
                } else {
                    print!("{}", status_text(&cfg.telemetry, &paths.data, attached.as_ref()));
                }
                Ok(0)
            }
            "test" => {
                let (cfg, _) = build(a)?;
                let endpoint = a.val("endpoint");
                if !cfg.telemetry.enabled && !a.flag("allow-disabled") {
                    return Err(crate::Fail::Usage("telemetry is disabled: set [telemetry] enabled = true (or pass --allow-disabled to probe anyway)".into()));
                }
                let c = crate::build_agent(a, crate::approver_for(a, false), false)?;
                if a.flag("json") {
                    match probe(&c.k, endpoint) {
                        Ok((url, code, spans)) => {
                            println!("{}", json!({"ok": true, "url": url, "status": code, "spans": spans}));
                            Ok(0)
                        }
                        Err(e) => {
                            println!("{}", json!({"ok": false, "url": url(&cfg.telemetry, endpoint), "error": e}));
                            Ok(1)
                        }
                    }
                } else {
                    match probe(&c.k, endpoint) {
                        Ok((url, code, spans)) => {
                            println!("✓ POST {url} → HTTP {code} ({spans} span{})", if spans == 1 { "" } else { "s" });
                            Ok(0)
                        }
                        Err(e) => {
                            eprintln!("✗ POST {} → {e}", url(&cfg.telemetry, endpoint));
                            Ok(1)
                        }
                    }
                }
            }
            other => Err(crate::Fail::Usage(format!("seagent telemetry: unknown action `{other}` (status, test)"))),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    fn cfg(f: impl FnOnce(&mut TelemetryConfig)) -> TelemetryConfig {
        let mut t = TelemetryConfig::default();
        f(&mut t);
        t
    }

    /// A fake OTLP collector: returns the request lines it received and its chosen status.
    fn collector(status: u16, takes: usize) -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let got = Arc::new(Mutex::new(Vec::<String>::new()));
        let g2 = got.clone();
        std::thread::spawn(move || {
            for s in l.incoming().take(takes) {
                let mut s = s.unwrap();
                let mut buf = vec![0u8; 65536];
                let mut req = Vec::new();
                loop {
                    let n = s.read(&mut buf).unwrap();
                    req.extend_from_slice(&buf[..n]);
                    let t = String::from_utf8_lossy(&req).to_string();
                    if let Some(i) = t.find("\r\n\r\n") {
                        let len = t.lines().find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                        if req.len() >= i + 4 + len {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                g2.lock().unwrap().push(String::from_utf8_lossy(&req).to_string());
                let _ = s.write_all(format!("HTTP/1.1 {status} X\r\ncontent-length: 2\r\n\r\n{{}}").as_bytes());
            }
        });
        (port, got)
    }

    #[test]
    fn status_reports_the_posture_without_leaking_header_values() {
        let data = seagent_core::tmp::scratch_path(format!("seagent-tel-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&data).unwrap();
        let t = cfg(|t| {
            t.enabled = true;
            t.endpoint = "http://collector.example:4318".into();
            t.headers.insert("x-api-key".into(), "sk-live-SECRETVALUE".into());
            t.service_name = "seagent".into();
        });
        let text = status_text(&t, &data, None);
        assert!(text.contains("Health export:  enabled"), "{text}");
        assert!(text.contains("http://collector.example:4318/v1/traces"), "{text}");
        assert!(text.contains("Headers:        1 (x-api-key)"), "{text}");
        assert!(text.contains("Redaction:      always on") && text.contains("Scope: gateway service health"), "{text}");
        assert!(!text.contains("SECRETVALUE"), "header values never print");
        let j = status_json(&t, &data, None);
        assert_eq!(j["headers"], json!(["x-api-key"]));
        assert_eq!(j["signals"], json!({"traces": true, "metrics": true, "logs": true}));
        assert_eq!(j["traces_url"], "http://collector.example:4318/v1/traces");
        assert!(!j.to_string().contains("SECRETVALUE"));
        // Disabled posture points at the config key that turns it on.
        let off = status_text(&cfg(|t| t.enabled = false), &data, None);
        assert!(off.contains("Health export:  disabled") && off.contains("seagent config set telemetry.enabled true"), "{off}");
        // `/v1/metrics` in a configured endpoint is rewritten to `/v1/traces`, as the daemon does.
        assert_eq!(url(&cfg(|t| t.endpoint = "http://h:4318/v1/metrics".into()), None), "http://h:4318/v1/traces");
        assert_eq!(url(&cfg(|_| {}), Some("http://other:9999")), "http://other:9999/v1/traces");
    }

    #[test]
    fn probe_posts_one_content_free_span_with_secret_headers() {
        let (port, got) = collector(200, 1);
        let k = crate::testkit::kit_with(|c| {
            c.telemetry.enabled = true;
            c.telemetry.endpoint = format!("http://127.0.0.1:{port}");
            c.telemetry.headers.insert("x-api-key".into(), "{{secret:OTLP_KEY}}".into());
        });
        k.k.vault.set("OTLP_KEY", "k-123").unwrap();
        let (u, code, spans) = probe(&k.k, None).unwrap();
        assert_eq!((code, spans), (200, 1));
        assert_eq!(u, format!("http://127.0.0.1:{port}/v1/traces"));
        let req = got.lock().unwrap()[0].clone();
        assert!(req.starts_with("POST /v1/traces "), "{req}");
        assert!(req.to_lowercase().contains("x-api-key: k-123"), "the secret header is resolved at send time: {req}");
        let body: Value = serde_json::from_str(&req[req.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "seagent.gateway_health");
        assert!(span["attributes"].as_array().unwrap().iter().any(|a| a["key"] == "seagent.event"));
        // Content-free: no session, message or prompt fields ride along.
        assert!(!req.contains("messages") && !req.contains("prompt"), "{req}");
        // `--endpoint` overrides the configured collector for one probe.
        let (port2, got2) = collector(200, 1);
        assert!(probe(&k.k, Some(&format!("http://127.0.0.1:{port2}"))).is_ok());
        assert!(got2.lock().unwrap()[0].contains("POST /v1/traces "));
    }

    #[test]
    fn probe_reports_collector_errors() {
        let (port, _) = collector(503, 1);
        let k = crate::testkit::kit_with(|c| {
            c.telemetry.enabled = true;
            c.telemetry.endpoint = format!("http://127.0.0.1:{port}");
        });
        let e = probe(&k.k, None).unwrap_err();
        assert!(e.contains("HTTP 503"), "{e}");
        // Unreachable collector: connection refused, surfaced not swallowed.
        assert!(probe(&k.k, Some("http://127.0.0.1:9")).is_err());
    }

    #[test]
    fn dispatch_owns_only_telemetry() {
        let _g = crate::testkit::env_lock();
        let k = crate::testkit::kit();
        std::env::set_var("SEAGENT_HOME", k.paths.data.parent().unwrap());
        assert!(COMMANDS.contains(&"telemetry"));
        assert!(dispatch("logs", &Args::parse(&[]).unwrap(), &[]).is_none());
        // `status` and `--json` work on a real (temp) home without touching the network.
        let a = Args::parse(&["--json".into()]).unwrap();
        assert_eq!(dispatch("telemetry", &a, &["status".into()]).map(|r| r.unwrap()), Some(0));
        // Unknown action is a usage error (exit 2 via main's Fail::Usage).
        let a = Args::parse(&["bogus".into()]).unwrap();
        assert!(matches!(dispatch("telemetry", &a, &["bogus".into()]), Some(Err(crate::Fail::Usage(_)))));
        // `test` refuses to probe when the config disables export.
        let a = Args::parse(&["test".into()]).unwrap();
        assert!(matches!(dispatch("telemetry", &a, &["test".into()]), Some(Err(crate::Fail::Usage(m))) if m.contains("disabled")));
    }
}
