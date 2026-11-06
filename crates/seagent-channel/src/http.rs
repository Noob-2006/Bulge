//! Outbound HTTP shared by the channels: JSON POST on a worker thread so a
//! blocked socket (Telegram long-poll) never delays cancellation.

use crate::{ChannelError, ChannelErrorKind as K};
use seagent_core::Cancel;
use std::io::Read;
use std::net::ToSocketAddrs;
use std::sync::mpsc;
use std::time::Duration;

const MAX_BODY: u64 = 16 * 1024 * 1024;
/// Largest number of redirect hops one channel request may follow.
const MAX_REDIRECTS: usize = 10;

// Unit tests point every channel at a loopback fake server. The guard still applies to
// production builds; a test can opt back into the real rule with `block_private_for_test`.
#[cfg(test)]
thread_local! {
    static ALLOW_PRIVATE_TESTS: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

#[cfg(test)]
fn private_allowed_for_test() -> bool {
    ALLOW_PRIVATE_TESTS.with(|c| c.get())
}

#[cfg(not(test))]
fn private_allowed_for_test() -> bool {
    false
}

#[cfg(test)]
pub(crate) struct PrivateTestGuard(bool);

#[cfg(test)]
impl Drop for PrivateTestGuard {
    fn drop(&mut self) {
        ALLOW_PRIVATE_TESTS.with(|c| c.set(self.0));
    }
}

#[cfg(test)]
pub(crate) fn block_private_for_test() -> PrivateTestGuard {
    let prev = ALLOW_PRIVATE_TESTS.with(|c| c.replace(false));
    PrivateTestGuard(prev)
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub body: String,
    /// Response headers, names lower-cased.
    pub headers: Vec<(String, String)>,
}

impl Resp {
    pub fn new(status: u16, body: impl Into<String>) -> Resp {
        Resp { status, retry_after: None, body: body.into(), headers: Vec::new() }
    }
    /// First value of a header (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn header_list(h: &ureq::http::HeaderMap) -> Vec<(String, String)> {
    h.iter().filter_map(|(k, v)| Some((k.as_str().to_ascii_lowercase(), v.to_str().ok()?.to_string()))).collect()
}

pub fn agent(timeout: Duration) -> ureq::Agent {
    seagent_net::http::builder()
        .http_status_as_error(false)
        // Redirects are followed by hand so every hop is vetted (see `Http::call`).
        .max_redirects(0)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(timeout))
        .build()
        .into()
}

fn post(agent: &ureq::Agent, url: &str, headers: &[(String, String)], body: &[u8]) -> Result<Resp, ChannelError> {
    let mut req = agent.post(url).header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(k, v);
    }
    // The URL may carry a bot token; never echo it in errors.
    let mut r = req.send(body).map_err(|e| ChannelError::new(K::Network, format!("request failed: {}", redact(&e.to_string()))))?;
    let status = r.status().as_u16();
    let retry_after = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok()).map(Duration::from_secs);
    let headers = header_list(r.headers());
    let mut raw = Vec::new();
    r.body_mut()
        .with_config()
        .limit(u64::MAX)
        .reader()
        .take(MAX_BODY)
        .read_to_end(&mut raw)
        .map_err(|e| ChannelError::new(K::Network, format!("reading response: {}", redact(&e.to_string()))))?;
    Ok(Resp { status, retry_after, body: String::from_utf8_lossy(&raw).into_owned(), headers })
}

/// `Ok(None)` when cancelled; the worker is abandoned and finishes on its own.
pub fn post_cancellable(agent: &ureq::Agent, url: &str, headers: &[(String, String)], body: Vec<u8>, cancel: &Cancel) -> Result<Option<Resp>, ChannelError> {
    let (tx, rx) = mpsc::channel();
    let (a, u, h) = (agent.clone(), url.to_string(), headers.to_vec());
    std::thread::spawn(move || {
        let _ = tx.send(post(&a, &u, &h, &body));
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(r) => return r.map(Some),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if cancel.is_cancelled() {
                    return Ok(None);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Network, "http worker died")),
        }
    }
}

/// Map an HTTP status to the error kind the delivery layer acts on.
pub fn classify(status: u16, retry_after: Option<Duration>, what: &str, body: &str) -> ChannelError {
    let snippet: String = redact(body).chars().take(300).collect();
    let kind = match status {
        401 | 403 => K::Auth,
        404 | 410 => K::NotFound,
        408 | 425 | 500..=599 => K::Network,
        429 => K::RateLimited { retry_after },
        _ => K::Protocol,
    };
    ChannelError::new(kind, format!("{what}: HTTP {status} {snippet}"))
}

/// Blocking request helper used by every HTTP channel. Bodies over `MAX_BODY` are cut.
#[derive(Clone)]
pub struct Http {
    pub agent: ureq::Agent,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Copy)]
pub enum Payload<'a> {
    None,
    Json(&'a serde_json::Value),
    Form(&'a [(&'a str, &'a str)]),
    Raw(&'a str, &'a [u8]),
    /// multipart/form-data: (name, filename, content-type, bytes); filename empty = plain field.
    Multipart(&'a [(&'a str, &'a str, &'a str, &'a [u8])]),
}

/// `scheme://host:port` of an http(s) URL — the unit of trust/redirect comparison.
fn origin_key(url: &str) -> Option<String> {
    let p = seagent_security::url_safety::parse(url)?;
    Some(format!("{}://{}:{}", p.scheme, p.host, p.port))
}

fn trust_key(url: &str) -> Option<String> {
    // A configured base may be a full URL or a bare `host[:port]`.
    let p = seagent_security::url_safety::parse(url).or_else(|| seagent_security::url_safety::parse(&format!("http://{}/", url.trim().trim_end_matches('/'))))?;
    Some(format!("{}:{}", p.host, p.port))
}

/// Refuse a URL that would reach cloud metadata or private space the operator did not
/// configure. `trusted` holds `host:port` pairs (the initial API origin for [`Http::call`],
/// or the channel's own base for [`get_bytes_trusted`]); a redirect to any other private
/// host is refused. DNS is resolved once per hop, as the media fetchers do.
fn vet_url(url: &str, trusted: &[String]) -> Result<(), ChannelError> {
    let block = |m: String| ChannelError::new(K::Protocol, format!("blocked URL: {m}"));
    let p = seagent_security::url_safety::parse_http(url).map_err(block)?;
    let key = format!("{}:{}", p.host, p.port);
    let is_trusted = trusted.contains(&key) || private_allowed_for_test();
    let policy = seagent_security::url_safety::UrlPolicy { allow_private_urls: is_trusted, fake_ip_ranges: Vec::new() };
    let hp = seagent_security::url_safety::HostPolicy { url: &policy, allowed_hostnames: &[], hostname_allowlist: &[], blocked_hostnames: &[] };
    seagent_security::url_safety::check_host(&p.host, &p.scheme, &hp).map_err(block)?;
    let ips = match p.host.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match (p.host.as_str(), p.port).to_socket_addrs() {
            Ok(v) => v.map(|a| a.ip()).collect(),
            // A configured proxy resolves the name; the connect-time policy cannot see it.
            Err(_) if seagent_security::url_safety::proxy_configured() => return Ok(()),
            Err(e) => return Err(ChannelError::new(K::Network, format!("cannot resolve {}: {e}", p.host))),
        },
    };
    if ips.is_empty() {
        return Err(ChannelError::new(K::Network, format!("cannot resolve {}: no addresses", p.host)));
    }
    seagent_security::url_safety::check_resolved(&p.host, &ips, &p.scheme, &hp).map_err(block)
}

/// Resolve a `Location` header against the URL that returned it (absolute,
/// scheme-relative or path-relative).
fn resolve_location(base: &str, loc: &str) -> String {
    let loc = loc.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    let origin = origin_key(base).unwrap_or_else(|| format!("{scheme}://{}", rest.split(['/', '?']).next().unwrap_or("")));
    if let Some(r) = loc.strip_prefix("//") {
        return format!("{scheme}://{r}");
    }
    if loc.starts_with('/') {
        return format!("{origin}{loc}");
    }
    let rest = &rest[rest.find('/').unwrap_or(rest.len())..];
    let path = rest.split(['?', '#']).next().unwrap_or("");
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    format!("{origin}{dir}/{loc}")
}

fn send_once(agent: &ureq::Agent, method: &str, url: &str, headers: &[(String, String)], ctype: Option<&str>, bytes: &[u8]) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
    match method {
        // DELETE with a body (Feishu `children/batch_delete`).
        "DELETE" if ctype.is_some() => {
            let mut r = agent.delete(url).force_send_body();
            if let Some(ct) = ctype {
                r = r.header("content-type", ct);
            }
            for (k, v) in headers {
                r = r.header(k.as_str(), v.as_str());
            }
            r.send(bytes)
        }
        "GET" | "DELETE" | "HEAD" => {
            let mut r = match method {
                "GET" => agent.get(url),
                "HEAD" => agent.head(url),
                _ => agent.delete(url),
            };
            for (k, v) in headers {
                r = r.header(k.as_str(), v.as_str());
            }
            r.call()
        }
        _ => {
            let mut r = match method {
                "PUT" => agent.put(url),
                "PATCH" => agent.patch(url),
                _ => agent.post(url),
            };
            if let Some(ct) = ctype {
                r = r.header("content-type", ct);
            }
            for (k, v) in headers {
                r = r.header(k.as_str(), v.as_str());
            }
            r.send(bytes)
        }
    }
}

fn read_resp(mut r: ureq::http::Response<ureq::Body>) -> Result<Resp, ChannelError> {
    let status = r.status().as_u16();
    let retry_after = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<f64>().ok()).map(|s| Duration::from_secs_f64(s.max(0.0)));
    let headers = header_list(r.headers());
    let mut raw = Vec::new();
    r.body_mut().with_config().limit(u64::MAX).reader().take(MAX_BODY).read_to_end(&mut raw).map_err(|e| ChannelError::new(K::Network, format!("reading response: {}", redact(&e.to_string()))))?;
    Ok(Resp { status, retry_after, body: String::from_utf8_lossy(&raw).into_owned(), headers })
}

impl Http {
    pub fn new(timeout: Duration) -> Http {
        Http { agent: agent(timeout), headers: Vec::new() }
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Http {
        self.headers.push((k.into(), v.into()));
        self
    }
    pub fn bearer(self, token: &str) -> Http {
        self.with_header("authorization", &format!("Bearer {token}"))
    }

    /// Raw call: (status, retry_after, body). Network failures are `Network` errors.
    ///
    /// The URL this call starts at is the operator-configured API origin for the channel, so
    /// it may be private. Every redirect is vetted separately: a hop to another private or
    /// metadata host is refused, hop headers (tokens) are dropped cross-origin, and at most
    /// [`MAX_REDIRECTS`] hops are followed.
    pub fn call(&self, method: &str, url: &str, extra: &[(&str, &str)], body: Payload) -> Result<Resp, ChannelError> {
        self.call_inner(method, url, extra, body, true)
    }

    /// [`Http::call`] without redirect following, for callers that read a 3xx themselves
    /// (the NIP-05 resolver refuses redirects). The initial URL is still vetted.
    pub fn call_once(&self, method: &str, url: &str, extra: &[(&str, &str)], body: Payload) -> Result<Resp, ChannelError> {
        self.call_inner(method, url, extra, body, false)
    }

    fn call_inner(&self, method: &str, url: &str, extra: &[(&str, &str)], body: Payload, follow: bool) -> Result<Resp, ChannelError> {
        let boundary = format!("seagent{}", std::process::id() as u64 * 7919 + std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0));
        let (mut ctype, mut bytes): (Option<String>, Vec<u8>) = match body {
            Payload::None => (None, Vec::new()),
            Payload::Json(v) => (Some("application/json".into()), serde_json::to_vec(v).unwrap_or_default()),
            Payload::Form(f) => (Some("application/x-www-form-urlencoded".into()), seagent_net::form_encode(f).into_bytes()),
            Payload::Raw(t, b) => (Some(t.into()), b.to_vec()),
            Payload::Multipart(parts) => {
                let mut b = Vec::new();
                for (name, file, ct, data) in parts {
                    b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                    if file.is_empty() {
                        b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes());
                    } else {
                        let ct = if ct.is_empty() { "application/octet-stream" } else { ct };
                        b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{}\"\r\nContent-Type: {ct}\r\n\r\n", file.replace('"', "")).as_bytes());
                    }
                    b.extend_from_slice(data);
                    b.extend_from_slice(b"\r\n");
                }
                b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
                (Some(format!("multipart/form-data; boundary={boundary}")), b)
            }
        };
        let mut hs: Vec<(String, String)> = self.headers.clone();
        hs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let initial = url.to_string();
        let trusted: Vec<String> = trust_key(&initial).into_iter().collect();
        let mut method = method.to_string();
        let mut current = initial.clone();
        let mut hops = 0usize;
        loop {
            vet_url(&current, &trusted)?;
            let same_origin = origin_key(&initial) == origin_key(&current);
            let headers: &[(String, String)] = if same_origin { &hs } else { &[] };
            let resp = send_once(&self.agent, &method, &current, headers, ctype.as_deref(), &bytes).map_err(|e| ChannelError::new(K::Network, format!("{method} request failed: {}", redact(&e.to_string()))))?;
            let status = resp.status().as_u16();
            if !follow || !(300..400).contains(&status) {
                return read_resp(resp);
            }
            let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).map(str::trim).filter(|l| !l.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, format!("{method}: HTTP {status} redirect without a Location header")))?;
            if hops >= MAX_REDIRECTS {
                return Err(ChannelError::new(K::Protocol, format!("{method}: too many redirects (more than {MAX_REDIRECTS})")));
            }
            hops += 1;
            let next = resolve_location(&current, loc);
            // 301/302/303 turn everything but GET/HEAD into a bodyless GET (RFC 7231);
            // 307/308 keep the method and body.
            if status == 303 || (matches!(status, 301 | 302) && method != "GET" && method != "HEAD") {
                method = "GET".into();
                ctype = None;
                bytes.clear();
            }
            current = next;
        }
    }

    /// Call and parse JSON, mapping non-2xx to classified errors.
    pub fn json(&self, method: &str, url: &str, body: Payload) -> Result<serde_json::Value, ChannelError> {
        let r = self.call(method, url, &[], body)?;
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, method, &r.body));
        }
        if r.body.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("{method}: bad JSON ({e}): {}", redact(&r.body.chars().take(200).collect::<String>()))))
    }
}

/// Download bytes with optional headers (auth), capped at `max`. The URL is treated as
/// untrusted: private/loopback and cloud-metadata targets are refused, and redirects are
/// followed only to public hosts (headers are dropped cross-origin). Channels that fetch
/// from their own configured base use [`get_bytes_trusted`].
pub fn get_bytes(url: &str, headers: &[(&str, &str)], max: u64) -> Result<Vec<u8>, ChannelError> {
    get_bytes_with(url, headers, max, &[])
}

/// [`get_bytes`] for a channel's own configured origin (`base`: a URL or `host[:port]`):
/// that origin may be private, any *other* private host reached by a redirect may not.
pub fn get_bytes_trusted(url: &str, headers: &[(&str, &str)], max: u64, base: &str) -> Result<Vec<u8>, ChannelError> {
    get_bytes_with(url, headers, max, &[base])
}

fn get_bytes_with(url: &str, headers: &[(&str, &str)], max: u64, base: &[&str]) -> Result<Vec<u8>, ChannelError> {
    let a = agent(Duration::from_secs(120));
    let trusted: Vec<String> = base.iter().filter_map(|b| trust_key(b)).collect();
    let initial = url.to_string();
    let mut current = initial.clone();
    let mut hops = 0usize;
    loop {
        vet_url(&current, &trusted)?;
        let same_origin = origin_key(&initial) == origin_key(&current);
        let mut r = a.get(&current);
        if same_origin {
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
        }
        let mut resp = r.call().map_err(|e| ChannelError::new(K::Network, format!("download failed: {}", redact(&e.to_string()))))?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).map(str::trim).filter(|l| !l.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, format!("download: HTTP {status} redirect without a Location header")))?;
            if hops >= MAX_REDIRECTS {
                return Err(ChannelError::new(K::Protocol, format!("download: too many redirects (more than {MAX_REDIRECTS})")));
            }
            hops += 1;
            current = resolve_location(&current, loc);
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(classify(status, None, "download", ""));
        }
        let mut raw = Vec::new();
        resp.body_mut().with_config().limit(u64::MAX).reader().take(max + 1).read_to_end(&mut raw).map_err(|e| ChannelError::new(K::Network, format!("download: {e}")))?;
        if raw.len() as u64 > max {
            return Err(ChannelError::new(K::Protocol, format!("attachment larger than {max} bytes")));
        }
        return Ok(raw);
    }
}

/// Strip `/bot<token>/` path segments from transport error strings.
pub fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("/bot") {
        out.push_str(&rest[..i + 4]);
        let tail = &rest[i + 4..];
        let end = tail.find(['/', ' ', '"', '\'']).unwrap_or(tail.len());
        out.push_str("***");
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;
    use std::time::Duration;

    #[test]
    fn redacts_bot_tokens() {
        assert_eq!(super::redact("GET https://api.telegram.org/bot123:ABC/getUpdates failed"), "GET https://api.telegram.org/bot***/getUpdates failed");
        assert_eq!(super::redact("no token here"), "no token here");
    }

    #[test]
    fn call_allows_the_configured_private_origin_but_blocks_redirects_to_other_private_hosts() {
        let _strict = block_private_for_test();
        let other = FakeServer::start(|_, _| (200, vec![], "should not be reached".into()));
        let target = format!("{}/steal", other.url);
        let srv = FakeServer::start(move |r, _| match r.path.as_str() {
            "/ok" => (200, vec![], "fine".into()),
            _ => (302, vec![("location".into(), target.clone())], String::new()),
        });
        let h = Http::new(Duration::from_secs(2));
        // The operator-configured base (here loopback) still works.
        assert_eq!(h.call("GET", &format!("{}/ok", srv.url), &[], Payload::None).unwrap().body, "fine");
        // A redirect to a *different* private host is refused before it is dialled.
        let e = h.call("GET", &format!("{}/go", srv.url), &[], Payload::None).unwrap_err();
        assert!(e.message.contains("private or internal"), "{}", e.message);
        assert!(other.requests().is_empty(), "the untrusted hop must not be connected to");
        // Cloud metadata is refused even as the initial target of a download.
        let e = get_bytes("http://169.254.169.254/latest/meta-data/", &[], 1024).unwrap_err();
        assert!(e.message.contains("cloud metadata"), "{}", e.message);
    }

    #[test]
    fn get_bytes_is_strict_and_the_trusted_form_allows_only_its_own_origin() {
        let _strict = block_private_for_test();
        let other = FakeServer::start(|_, _| (200, vec![], "other".into()));
        let target = format!("{}/other", other.url);
        let srv = FakeServer::start(move |r, _| match r.path.as_str() {
            "/ok" => (200, vec![], "bytes".into()),
            "/same" => (302, vec![("location".into(), "/ok".into())], String::new()),
            _ => (302, vec![("location".into(), target.clone())], String::new()),
        });
        // Untrusted loopback (e.g. a Discord attachment URL) is refused before connecting.
        let e = get_bytes(&format!("{}/ok", srv.url), &[], 1024).unwrap_err();
        assert!(e.message.contains("private or internal"), "{}", e.message);
        assert!(srv.requests().is_empty(), "no connection may be made");
        // The channel's own configured base may be private, including a same-origin redirect.
        assert_eq!(get_bytes_trusted(&format!("{}/same", srv.url), &[], 1024, &srv.url).unwrap(), b"bytes");
        // …but not a redirect to another private origin.
        let e = get_bytes_trusted(&format!("{}/off", srv.url), &[], 1024, &srv.url).unwrap_err();
        assert!(e.message.contains("private or internal"), "{}", e.message);
        assert!(other.requests().is_empty(), "the untrusted hop must not be connected to");
    }
}
