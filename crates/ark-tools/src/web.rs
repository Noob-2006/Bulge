use crate::util::truncate_str;
use ark_core::tool::{arg_opt_str, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use regex::Regex;
use serde_json::{json, Value};
use std::io::Read as _;
use std::sync::OnceLock;
use std::time::Duration;

const MAX_BODY: u64 = 4 * 1024 * 1024;
const MAX_TEXT: usize = 100 * 1024;

/// Host of an http(s) URL, or an error explaining what is wrong.
fn parse_host(url: &str) -> Result<&str, String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| format!("only http:// and https:// URLs are allowed, got `{}`", truncate_str(url, 80)))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        host_port.split(']').next().map(|h| &h[1..]).unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err(format!("URL has no host: `{}`", truncate_str(url, 80)));
    }
    Ok(host)
}

fn headers_of(input: &Value) -> Result<Vec<(String, String)>, String> {
    match input.get("headers") {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())).ok_or_else(|| format!("header `{k}` must be a string")))
            .collect(),
        Some(_) => Err("`headers` must be an object of string values".into()),
    }
}

pub fn html_to_text(html: &str) -> String {
    static RES: OnceLock<[Regex; 4]> = OnceLock::new();
    let [blocks, breaks, tags, spaces] = RES.get_or_init(|| {
        [
            Regex::new(r"(?is)<(script|style|noscript|svg|head)\b.*?</(script|style|noscript|svg|head)\s*>|<!--.*?-->").unwrap(),
            Regex::new(r"(?i)<(br|/p|/div|/li|/h[1-6]|/tr|/section|/article)\b[^>]*>").unwrap(),
            Regex::new(r"(?s)<[^>]*>").unwrap(),
            Regex::new(r"[ \t\r\f]+").unwrap(),
        ]
    });
    let s = blocks.replace_all(html, " ");
    let s = breaks.replace_all(&s, "\n");
    let s = tags.replace_all(&s, " ");
    let s = s
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    let s = spaces.replace_all(&s, " ");
    let mut out = String::new();
    let mut blank = 0;
    for line in s.lines().map(str::trim) {
        if line.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim().to_string()
}

pub struct WebFetch;

impl Tool for WebFetch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "web_fetch".into(),
            description: "Fetch a URL over HTTP(S) and return status and text (HTML is converted to plain text).".into(),
            input_schema: json!({"type":"object","properties":{
                "url":{"type":"string"},
                "method":{"type":"string","enum":["GET","POST"],"default":"GET"},
                "body":{"type":"string"},
                "headers":{"type":"object","additionalProperties":{"type":"string"}}},
                "required":["url"]}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let Ok(url) = arg_str(input, "url") else { return vec![] };
        let Ok(host) = parse_host(url) else { return vec![] };
        let mut payload = String::new();
        if let Some(Value::Object(h)) = input.get("headers") {
            for (k, v) in h {
                payload.push_str(&format!("{k}: {}\n", v.as_str().unwrap_or("")));
            }
        }
        if let Some(b) = arg_opt_str(input, "body") {
            payload.push_str(b);
        }
        // The full URL can carry data too (query strings).
        vec![Effect::Net { dest: host.to_string(), payload: format!("{url}\n{payload}") }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let url = match arg_str(&input, "url") {
            Ok(u) => (ctx.secrets)(u),
            Err(e) => return ToolOutput::err(e),
        };
        if let Err(e) = parse_host(&url) {
            return ToolOutput::err(e);
        }
        let method = arg_opt_str(&input, "method").unwrap_or("GET").to_ascii_uppercase();
        let headers = match headers_of(&input) {
            Ok(h) => h,
            Err(e) => return ToolOutput::err(e),
        };
        let body = arg_opt_str(&input, "body").map(|b| (ctx.secrets)(b));
        if ctx.cancel.is_cancelled() {
            return ToolOutput::err("cancelled");
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .max_redirects(5)
            .build()
            .into();
        let result = match method.as_str() {
            "GET" => {
                if body.is_some() {
                    return ToolOutput::err("GET requests cannot carry a body; use method POST");
                }
                let mut req = agent.get(&url);
                for (k, v) in &headers {
                    req = req.header(k, (ctx.secrets)(v));
                }
                req.call()
            }
            "POST" => {
                let mut req = agent.post(&url);
                for (k, v) in &headers {
                    req = req.header(k, (ctx.secrets)(v));
                }
                req.send(body.unwrap_or_default().as_bytes())
            }
            m => return ToolOutput::err(format!("unsupported method `{m}`; use GET or POST")),
        };
        let mut resp = match result {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(format!("request to {} failed: {e}", truncate_str(&url, 200))),
        };
        let status = resp.status().as_u16();
        let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
        let mut raw = Vec::new();
        let read = resp.body_mut().with_config().limit(u64::MAX).reader().take(MAX_BODY + 1).read_to_end(&mut raw);
        if let Err(e) = read {
            return ToolOutput::err(format!("HTTP {status}: failed reading body: {e}"));
        }
        let over = raw.len() as u64 > MAX_BODY;
        raw.truncate(MAX_BODY as usize);
        if !ctype.is_empty() && !(ctype.starts_with("text/") || ctype.contains("json") || ctype.contains("xml") || ctype.contains("javascript")) {
            return ToolOutput { content: format!("HTTP {status}, content-type {ctype}, {} bytes (binary body not shown)", raw.len()), is_error: status >= 400, ui_resource: None };
        }
        let text = String::from_utf8_lossy(&raw);
        let text = if ctype.contains("html") || (ctype.is_empty() && text.trim_start().starts_with('<')) { html_to_text(&text) } else { text.into_owned() };
        let shown = truncate_str(&text, MAX_TEXT);
        let mut out = format!("HTTP {status}\n\n{shown}");
        if shown.len() < text.len() || over {
            out.push_str("\n…[body truncated]");
        }
        ToolOutput { content: out, is_error: status >= 400, ui_resource: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// One-shot HTTP server; returns base URL and a receiver for the raw request head+body.
    fn serve(status: &str, ctype: &str, body: Vec<u8>) -> (String, mpsc::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let status = status.to_string();
        let ctype = ctype.to_string();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                head.push_str(&line);
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).unwrap();
            head.push_str(&String::from_utf8_lossy(&b));
            tx.send(head).unwrap();
            let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = s.write_all(&body);
        });
        (format!("http://{addr}"), rx)
    }

    #[test]
    fn get_html_is_stripped() {
        let c = ctx("web");
        let (url, rx) = serve("200 OK", "text/html; charset=utf-8", b"<html><head><title>t</title><script>evil()</script></head><body><h1>Hello</h1><p>a &amp; b</p></body></html>".to_vec());
        let o = WebFetch.call(&c, json!({"url": format!("{url}/x?q=1")}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.starts_with("HTTP 200"));
        assert!(o.content.contains("Hello") && o.content.contains("a & b") && !o.content.contains("evil"));
        assert!(rx.recv().unwrap().starts_with("GET /x?q=1"));
    }

    #[test]
    fn post_substitutes_secrets_but_effects_do_not() {
        let c = ctx("webpost");
        let (url, rx) = serve("201 Created", "application/json", br#"{"ok":true}"#.to_vec());
        let input = json!({"url":url,"method":"POST","body":"key={{secret:TOKEN}}","headers":{"X-Auth":"{{secret:TOKEN}}"}});
        let eff = WebFetch.effects(&c, &input);
        match &eff[..] {
            [Effect::Net { dest, payload }] => {
                assert_eq!(dest, "127.0.0.1");
                assert!(payload.contains("key={{secret:TOKEN}}") && !payload.contains("s3cr3t"));
                assert!(payload.contains("X-Auth: {{secret:TOKEN}}"));
            }
            other => panic!("{other:?}"),
        }
        let o = WebFetch.call(&c, input);
        assert!(!o.is_error && o.content.contains(r#"{"ok":true}"#), "{}", o.content);
        let req = rx.recv().unwrap().to_ascii_lowercase();
        assert!(req.contains("key=s3cr3t") && req.contains("x-auth: s3cr3t"), "{req}");
    }

    #[test]
    fn http_error_status_is_error_with_body() {
        let c = ctx("web404");
        let (url, _rx) = serve("404 Not Found", "text/plain", b"nothing here".to_vec());
        let o = WebFetch.call(&c, json!({"url":url}));
        assert!(o.is_error && o.content.contains("HTTP 404") && o.content.contains("nothing here"));
    }

    #[test]
    fn binary_and_oversized_bodies() {
        let c = ctx("webbin");
        let (url, _rx) = serve("200 OK", "image/png", vec![0x89, b'P', b'N', b'G', 0]);
        let o = WebFetch.call(&c, json!({"url":url}));
        assert!(o.content.contains("binary body not shown"));
        let (url, _rx) = serve("200 OK", "text/plain", vec![b'a'; 300_000]);
        let o = WebFetch.call(&c, json!({"url":url}));
        assert!(o.content.contains("body truncated") && o.content.len() < 110_000);
    }

    #[test]
    fn failures() {
        let c = ctx("webf");
        assert!(WebFetch.call(&c, json!({})).is_error);
        let o = WebFetch.call(&c, json!({"url":"ftp://example.com/x"}));
        assert!(o.is_error && o.content.contains("only http"));
        assert!(WebFetch.call(&c, json!({"url":"http:///nohost"})).content.contains("no host"));
        assert!(WebFetch.call(&c, json!({"url":"http://127.0.0.1:9/","method":"DELETE"})).content.contains("unsupported method"));
        assert!(WebFetch.call(&c, json!({"url":"http://127.0.0.1:9/","body":"x"})).content.contains("cannot carry a body"));
        assert!(WebFetch.call(&c, json!({"url":"http://127.0.0.1:9/","headers":["x"]})).content.contains("headers"));
        assert!(WebFetch.call(&c, json!({"url":"http://127.0.0.1:9/","headers":{"a":1}})).is_error);
        // Port grabbed then released: connection refused.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let o = WebFetch.call(&c, json!({"url": format!("http://127.0.0.1:{port}/")}));
        assert!(o.is_error && o.content.contains("failed"), "{}", o.content);
        assert!(WebFetch.effects(&c, &json!({"url":"ftp://x"})).is_empty());
        c.cancel.cancel();
        assert_eq!(WebFetch.call(&c, json!({"url":"http://127.0.0.1:9/"})).content, "cancelled");
    }

    #[test]
    fn host_parsing() {
        assert_eq!(parse_host("https://user:pw@api.x.com:8443/p?q").unwrap(), "api.x.com");
        assert_eq!(parse_host("http://[::1]:80/").unwrap(), "::1");
        assert_eq!(parse_host("https://a.b").unwrap(), "a.b");
    }
}
