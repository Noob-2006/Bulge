//! Blocking HTTP for media providers: JSON, multipart, binary bodies, downloads and
//! async-job polling. Every non-2xx answer becomes an error carrying the provider's
//! own message (`error.message`, `detail`, `message`…) and never the API key.

use ark_core::Cancel;
use serde_json::Value;
use std::io::Read;
use std::time::{Duration, Instant};

/// Largest response body read (generated video can be big).
pub const MAX_BODY: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    pub fn content_type(&self) -> String {
        self.header("content-type").unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase()
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> Result<Value, String> {
        if self.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&self.body).map_err(|e| format!("bad JSON from provider ({e}): {}", excerpt(&self.text(), 200)))
    }
    /// `Err` with the provider's message unless 2xx.
    pub fn check(self, what: &str) -> Result<Resp, String> {
        if self.ok() {
            Ok(self)
        } else {
            Err(format!("{what}: HTTP {}: {}", self.status, error_message(&self.text())))
        }
    }
}

/// The human-readable part of a provider error body.
pub fn error_message(body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let pick = |v: &Value| -> Option<String> {
        match v {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Object(_) => v["message"].as_str().or_else(|| v["msg"].as_str()).map(str::to_string),
            Value::Array(a) => a.first().and_then(|x| x["msg"].as_str().or_else(|| x["message"].as_str())).map(str::to_string),
            _ => None,
        }
    };
    for k in ["error", "detail", "message", "errors", "error_message", "base_resp"] {
        if let Some(s) = pick(&v[k]) {
            return excerpt(&s, 500);
        }
    }
    if let Some(s) = v["status_msg"].as_str().or_else(|| v["base_resp"]["status_msg"].as_str()) {
        return excerpt(s, 500);
    }
    excerpt(body.trim(), 500)
}

pub fn excerpt(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// A multipart/form-data body.
#[derive(Debug, Clone, Default)]
pub struct Multipart {
    parts: Vec<(String, Option<String>, String, Vec<u8>)>,
}

impl Multipart {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn text(mut self, name: &str, value: impl Into<String>) -> Self {
        self.parts.push((name.into(), None, String::new(), value.into().into_bytes()));
        self
    }
    pub fn file(mut self, name: &str, filename: &str, mime: &str, data: Vec<u8>) -> Self {
        self.parts.push((name.into(), Some(filename.into()), mime.into(), data));
        self
    }
    /// `(content-type, body)`.
    pub fn encode(&self) -> (String, Vec<u8>) {
        let boundary = format!("----arkmedia{:016x}", seed());
        let mut b = Vec::new();
        for (name, file, mime, data) in &self.parts {
            b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match file {
                None => b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes()),
                Some(f) => {
                    let ct = if mime.is_empty() { "application/octet-stream" } else { mime };
                    b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{}\"\r\nContent-Type: {ct}\r\n\r\n", f.replace('"', "")).as_bytes());
                }
            }
            b.extend_from_slice(data);
            b.extend_from_slice(b"\r\n");
        }
        b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={boundary}"), b)
    }
}

fn seed() -> u64 {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    t ^ (std::process::id() as u64).rotate_left(32)
}

/// Largest number of redirect hops one result download may follow.
const MAX_REDIRECTS: usize = 10;

/// Connect-time re-check for provider-supplied URLs (A15): the URL policy is applied to the
/// address ureq is *about to dial*, not only to the URL, so a DNS answer that changes between
/// the check and the connection (rebinding) cannot reach the LAN or cloud metadata. The
/// decision itself is [`crate::vision::UrlPolicy::check_resolved`] — one implementation.
#[derive(Debug, Clone)]
struct PinnedResolver {
    policy: crate::vision::UrlPolicy,
}

impl ureq::unversioned::resolver::Resolver for PinnedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let name = uri.host().unwrap_or("").to_ascii_lowercase();
        let addrs = ureq::unversioned::resolver::DefaultResolver::default().resolve(uri, config, timeout)?;
        let ips: Vec<std::net::IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        // Keep the port: a trusted `host:port` must not extend trust to other ports.
        let host = match uri.port_u16() {
            Some(p) => format!("{name}:{p}"),
            None => name,
        };
        self.policy.check_resolved(&host, &ips).map_err(|m| ureq::Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, m)))?;
        Ok(addrs)
    }
}

#[derive(Clone)]
pub struct Http {
    agent: ureq::Agent,
    /// Kept so a guarded client (which needs the policy at call time) has the same limits.
    timeout: Duration,
}

impl Default for Http {
    fn default() -> Self {
        Http::new(Duration::from_secs(600))
    }
}

pub type Headers = [(String, String)];

impl Http {
    pub fn new(timeout: Duration) -> Self {
        let agent = ureq::Agent::config_builder().http_status_as_error(false).max_redirects(10).timeout_connect(Some(Duration::from_secs(20))).timeout_global(Some(timeout)).build().into();
        Http { agent, timeout }
    }

    /// A client for **provider-supplied** URLs: no redirects (every hop is vetted by the caller)
    /// and [`PinnedResolver`] checks the address that is actually dialled.
    fn guarded(&self, cfg: &crate::MediaConfig) -> ureq::Agent {
        let conf = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(20)))
            .timeout_global(Some(self.timeout))
            .build();
        ureq::Agent::with_parts(conf, ureq::unversioned::transport::DefaultConnector::default(), PinnedResolver { policy: crate::vision::UrlPolicy::for_config(cfg) })
    }

    /// Any method; `body` = `(content-type, bytes)`.
    pub fn send(&self, method: &str, url: &str, headers: &Headers, body: Option<(&str, &[u8])>) -> Result<Resp, String> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(format!("not an http(s) URL: {}", excerpt(url, 120)));
        }
        let resp = match method {
            "GET" | "DELETE" | "HEAD" if body.is_none() => {
                let mut r = match method {
                    "GET" => self.agent.get(url),
                    "HEAD" => self.agent.head(url),
                    _ => self.agent.delete(url),
                };
                for (k, v) in headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.call()
            }
            _ => {
                let mut r = match method {
                    "PUT" => self.agent.put(url),
                    "PATCH" => self.agent.patch(url),
                    "DELETE" => self.agent.delete(url).force_send_body(),
                    _ => self.agent.post(url),
                };
                let (ct, bytes) = body.unwrap_or(("application/json", b""));
                if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                    r = r.header("content-type", ct);
                }
                for (k, v) in headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.send(bytes)
            }
        };
        read(resp.map_err(|e| format!("{method} {} failed: {e}", host_of(url)))?, url)
    }

    /// One `GET` that never follows a redirect (`download` vets each hop itself).
    fn get_once(&self, agent: &ureq::Agent, url: &str, headers: &Headers) -> Result<Resp, String> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(format!("not an http(s) URL: {}", excerpt(url, 120)));
        }
        let mut r = agent.get(url);
        for (k, v) in headers {
            r = r.header(k.as_str(), v.as_str());
        }
        read(r.call().map_err(|e| format!("GET {} failed: {e}", host_of(url)))?, url)
    }

    pub fn post_json(&self, url: &str, headers: &Headers, body: &Value) -> Result<Value, String> {
        let b = serde_json::to_vec(body).unwrap_or_default();
        self.send("POST", url, headers, Some(("application/json", &b)))?.check(&host_of(url))?.json()
    }
    /// POST JSON, expect a binary body back (audio, images).
    pub fn post_json_bytes(&self, url: &str, headers: &Headers, body: &Value) -> Result<Resp, String> {
        let b = serde_json::to_vec(body).unwrap_or_default();
        self.send("POST", url, headers, Some(("application/json", &b)))?.check(&host_of(url))
    }
    pub fn post_multipart(&self, url: &str, headers: &Headers, form: &Multipart) -> Result<Resp, String> {
        let (ct, b) = form.encode();
        self.send("POST", url, headers, Some((&ct, &b)))?.check(&host_of(url))
    }
    pub fn post_form(&self, url: &str, headers: &Headers, pairs: &[(&str, &str)]) -> Result<Resp, String> {
        let b = ark_net::form_encode(pairs);
        self.send("POST", url, headers, Some(("application/x-www-form-urlencoded", b.as_bytes())))?.check(&host_of(url))
    }
    pub fn get_json(&self, url: &str, headers: &Headers) -> Result<Value, String> {
        self.send("GET", url, headers, None)?.check(&host_of(url))?.json()
    }
    pub fn get(&self, url: &str, headers: &Headers) -> Result<Resp, String> {
        self.send("GET", url, headers, None)?.check(&host_of(url))
    }
    /// A vetted `GET` for a **provider-supplied** URL: the url-safety decision from `cfg`
    /// ([`crate::vision::UrlPolicy`], the same one the web tools make) is applied to the URL
    /// *and to every redirect hop*, so a hostile provider cannot make the daemon read cloud
    /// metadata or the LAN. The caller's headers only travel to the original host, so an API
    /// key never follows a redirect. A non-2xx answer becomes the provider's error message.
    fn get_checked(&self, cfg: &crate::MediaConfig, url: &str, headers: &Headers) -> Result<Resp, String> {
        let policy = crate::vision::UrlPolicy::for_config(cfg);
        let agent = self.guarded(cfg);
        let start_host = host_of(url);
        let mut url = url.to_string();
        let mut hops = 0;
        loop {
            policy.check(&url)?;
            let same_host = host_of(&url) == start_host;
            let r = self.get_once(&agent, &url, if same_host { headers } else { &[] })?;
            if !(300..400).contains(&r.status) {
                return r.check(&host_of(&url));
            }
            let loc = r.header("location").map(str::trim).filter(|l| !l.is_empty()).ok_or_else(|| format!("{}: HTTP {} redirect without a Location header", host_of(&url), r.status))?;
            if hops >= MAX_REDIRECTS {
                return Err(format!("{start_host}: too many redirects (more than {MAX_REDIRECTS})"));
            }
            hops += 1;
            url = resolve_location(&url, loc);
        }
    }

    /// Download a provider-hosted result (`data:` URLs decoded in place), vetted per hop.
    pub fn download(&self, cfg: &crate::MediaConfig, url: &str, headers: &Headers) -> Result<(Vec<u8>, String), String> {
        if let Some((mime, bytes)) = crate::store::decode_data_url(url) {
            return Ok((bytes, mime));
        }
        let r = self.get_checked(cfg, url, headers)?;
        let ct = r.content_type();
        Ok((r.body, ct))
    }

    /// `GET` a provider-supplied JSON URL under the same vetted policy as [`Http::download`]
    /// (fal hands back `status_url`/`response_url`; a hostile answer must not reach the LAN).
    pub fn get_json_checked(&self, cfg: &crate::MediaConfig, url: &str, headers: &Headers) -> Result<Value, String> {
        self.get_checked(cfg, url, headers)?.json()
    }
}

pub fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', '?']).next().unwrap_or("").to_string()
}

/// Collect a ureq response into a [`Resp`], capped at [`MAX_BODY`].
fn read(mut r: ureq::http::Response<ureq::Body>, url: &str) -> Result<Resp, String> {
    let status = r.status().as_u16();
    let headers = r.headers().iter().filter_map(|(k, v)| Some((k.as_str().to_ascii_lowercase(), v.to_str().ok()?.to_string()))).collect();
    let mut raw = Vec::new();
    r.body_mut().with_config().limit(u64::MAX).reader().take(MAX_BODY).read_to_end(&mut raw).map_err(|e| format!("reading response from {}: {e}", host_of(url)))?;
    Ok(Resp { status, headers, body: raw })
}

/// Resolve a `Location` header against the URL that returned it (absolute,
/// scheme-relative or path-relative).
fn resolve_location(base: &str, loc: &str) -> String {
    let loc = loc.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    let origin = format!("{scheme}://{}", host_of(base));
    if let Some(r) = loc.strip_prefix("//") {
        return format!("{scheme}://{r}");
    }
    if loc.starts_with('/') {
        return format!("{origin}{loc}");
    }
    let path = {
        let rest = &rest[rest.find('/').unwrap_or(rest.len())..];
        rest.split(['?', '#']).next().unwrap_or("")
    };
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    format!("{origin}{dir}/{loc}")
}

/// Poll `step` every `every` until it returns `Some`, `timeout` passes or `cancel` fires.
pub fn poll<T>(cancel: &Cancel, every: Duration, timeout: Duration, mut step: impl FnMut() -> Result<Option<T>, String>) -> Result<T, String> {
    let start = Instant::now();
    loop {
        if let Some(v) = step()? {
            return Ok(v);
        }
        if start.elapsed() >= timeout {
            return Err(format!("timed out after {}s waiting for the provider", timeout.as_secs()));
        }
        let until = Instant::now() + every;
        while Instant::now() < until {
            if cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            std::thread::sleep(Duration::from_millis(20).min(every));
        }
    }
}

/// Poll interval for async jobs (`ARK_MEDIA_POLL_MS` shortens it in tests).
pub fn poll_every(default_ms: u64) -> Duration {
    Duration::from_millis(std::env::var("ARK_MEDIA_POLL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(default_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;

    #[test]
    fn json_multipart_and_errors() {
        let srv = FakeServer::start(|r, _| match r.path.as_str() {
            "/ok" => (200, vec![], format!("{{\"len\":{}}}", r.raw.len())),
            _ => (401, vec![], "{\"error\":{\"message\":\"Incorrect API key\"}}".into()),
        });
        let h = Http::default();
        let v = h.post_json(&format!("{}/ok", srv.url), &[], &serde_json::json!({"a": 1})).unwrap();
        assert_eq!(v["len"], 7);
        let e = h.post_json(&format!("{}/bad", srv.url), &[("authorization".into(), "Bearer sk-secret".into())], &Value::Null).unwrap_err();
        assert!(e.contains("HTTP 401: Incorrect API key") && !e.contains("sk-secret"), "{e}");
        let form = Multipart::new().text("model", "whisper-1").file("file", "a.ogg", "audio/ogg", b"OGG".to_vec());
        let r = h.post_multipart(&format!("{}/ok", srv.url), &[], &form).unwrap();
        assert!(r.ok());
        let seen = srv.seen.lock().unwrap();
        let body = String::from_utf8_lossy(&seen[2].raw).to_string();
        assert!(seen[2].header("content-type").unwrap().starts_with("multipart/form-data; boundary="));
        assert!(body.contains("name=\"model\"\r\n\r\nwhisper-1") && body.contains("filename=\"a.ogg\"\r\nContent-Type: audio/ogg\r\n\r\nOGG"), "{body}");
    }

    #[test]
    fn error_message_shapes() {
        assert_eq!(error_message("{\"detail\":[{\"msg\":\"field required\"}]}"), "field required");
        assert_eq!(error_message("{\"message\":\"nope\"}"), "nope");
        assert_eq!(error_message("plain"), "plain");
        assert_eq!(error_message("{\"base_resp\":{\"status_code\":1004,\"status_msg\":\"login fail\"}}"), "login fail");
    }

    /// A loopback listener that counts accepted connections and never answers. Stands in for
    /// a LAN host or the cloud-metadata address: 169.254.169.254 cannot be bound in CI, so a
    /// refused fetch is proven by "the listener saw zero connections", and the positive
    /// control proves the counter really observes connections.
    struct Silent {
        url: String,
        conns: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Silent {
        fn start() -> Silent {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            let conns = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let n = conns.clone();
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for s in l.incoming() {
                    let Ok(s) = s else { continue };
                    n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    held.push(s);
                }
            });
            Silent { url, conns }
        }
        fn conns(&self) -> usize {
            self.conns.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn media_at(base: &str, extra: &str) -> crate::Media {
        crate::Media { cfg: crate::testutil::cfg_for("fal", base, extra), http: Http::new(Duration::from_secs(2)) }
    }

    #[test]
    fn connect_time_check_refuses_an_untrusted_address_before_dialling() {
        // A15 (DNS rebinding): the policy is applied again to the address that is actually
        // dialled, so a name that resolved differently between `policy.check` and the connect
        // cannot reach the LAN. Here the URL policy is bypassed on purpose (we call the guarded
        // agent directly): the resolver alone must refuse, and the listener must see nothing.
        let silent = Silent::start();
        let strict = Http::new(Duration::from_secs(2)).guarded(&crate::testutil::cfg_for("fal", "https://fal.run", ""));
        let e = strict.get(&format!("{}/x", silent.url)).call().unwrap_err();
        assert!(e.to_string().contains("private/internal address"), "{e}");
        assert_eq!(silent.conns(), 0, "nothing may be dialled");
        // The same address is fine when it is the operator's configured provider origin.
        let trusted = Http::new(Duration::from_secs(2)).guarded(&crate::testutil::cfg_for("fal", &silent.url, ""));
        let _ = trusted.get(&format!("{}/x", silent.url)).call();
        assert_eq!(silent.conns(), 1, "a trusted origin is connected to");
    }

    #[test]
    fn download_lets_a_configured_private_origin_through() {
        let srv = FakeServer::start_raw(|_, _| (200, vec![("content-type".into(), "image/png".into())], b"\x89PNG\r\n\x1a\n".to_vec()));
        // The operator pointed the provider at loopback (local ComfyUI / LiteLLM-style proxy):
        // its own origin stays reachable.
        let m = media_at(&srv.url, "");
        let (bytes, ct) = m.download(&format!("{}/out.png", srv.url), &[]).unwrap();
        assert_eq!((bytes.as_slice(), ct.as_str()), (&b"\x89PNG\r\n\x1a\n"[..], "image/png"));
        // `[media] allow_private_urls = true` opens private space generally (the web-tool toggle).
        let open = media_at("http://127.0.0.1:9", "allow_private_urls = true");
        let (bytes, _) = open.download(&format!("{}/out.png", srv.url), &[]).unwrap();
        assert_eq!(bytes.len(), 8);
        // A strict config refuses the same loopback result URL before connecting.
        let strict = crate::Media { cfg: crate::testutil::cfg_for("fal", "https://fal.run", ""), http: Http::new(Duration::from_secs(2)) };
        let e = strict.download(&format!("{}/out.png", srv.url), &[]).unwrap_err();
        assert!(e.contains("private/internal address"), "{e}");
    }

    #[test]
    fn download_refuses_cloud_metadata_before_any_request() {
        // Even with private URLs allowed, the metadata floor holds (vision::check_url).
        let m = media_at("http://127.0.0.1:9", "allow_private_urls = true");
        for url in ["http://169.254.169.254/latest/meta-data/", "http://169.254.170.2/v2/credentials", "http://100.100.100.200/latest/meta-data/", "http://[fd00:ec2::254]/latest/meta-data/"] {
            let e = m.download(url, &[]).unwrap_err();
            assert!(e.contains("cloud metadata"), "{url}: {e}");
        }
        let e = m.download("http://metadata.google.internal/computeMetadata/v1/", &[]).unwrap_err();
        assert!(e.contains("internal hostname"), "{e}");
        // Provider-supplied *JSON* URLs (fal `status_url`) go through the same guard.
        let e = m.get_json_checked("http://169.254.169.254/latest/meta-data/", &[]).unwrap_err();
        assert!(e.contains("cloud metadata"), "{e}");

        // A redirect is vetted too: hop 1 is a private address the policy does not trust, so
        // it is refused *before connecting* (the listener saw zero connections).
        let meta = Silent::start();
        let target = format!("{}/latest/meta-data/", meta.url);
        let srv = FakeServer::start(move |_, _| (302, vec![("location".into(), target.clone())], String::new()));
        let m = media_at(&srv.url, "");
        let e = m.download(&format!("{}/out.mp4", srv.url), &[("authorization".into(), "Bearer sk-live".into())]).unwrap_err();
        assert!(e.contains("private/internal address"), "{e}");
        assert_eq!(meta.conns(), 0, "no connection may reach the redirect target");
        assert_eq!(srv.requests().len(), 1, "the redirect must not be followed");

        // The same through a cloud-metadata URL: refused on the hop, not on the provider.
        let srv = FakeServer::start(|_, _| (302, vec![("location".into(), "http://169.254.169.254/latest/meta-data/".into())], String::new()));
        let m = media_at(&srv.url, "");
        let e = m.download(&format!("{}/out.mp4", srv.url), &[]).unwrap_err();
        assert!(e.contains("cloud metadata"), "{e}");
        assert_eq!(srv.requests().len(), 1);

        // Control: the counter does see a connection when a URL is allowed to reach it.
        let m = media_at("http://127.0.0.1:9", "allow_private_urls = true");
        assert!(m.download(&meta.url, &[]).is_err(), "the stand-in listener never answers");
        assert_eq!(meta.conns(), 1, "the stand-in listener is reachable and counted");
    }

    #[test]
    fn download_follows_redirects_without_leaking_the_key() {
        // Two operator-configured origins: the provider and the CDN it redirects to.
        let cdn = FakeServer::start_raw(|r, _| {
            if r.path == "/cdn/final.mp3" {
                (200, vec![("content-type".into(), "audio/mpeg".into())], b"MP3".to_vec())
            } else {
                // A relative Location is resolved against the URL that returned it.
                (302, vec![("location".into(), "final.mp3".into())], vec![])
            }
        });
        let there = cdn.url.clone();
        let srv = FakeServer::start(move |r, _| {
            assert_eq!(r.path, "/start");
            (302, vec![("location".into(), format!("{there}/cdn/out.mp3"))], String::new())
        });
        let cfg = crate::testutil::cfg_for("fal", &srv.url, &format!("[providers.cdn]\napi_key = \"k\"\nbase_url = \"{}\"\n", cdn.url));
        let m = crate::Media { cfg, http: Http::new(Duration::from_secs(2)) };
        let (bytes, ct) = m.download(&format!("{}/start", srv.url), &[("authorization".into(), "Bearer sk-live".into())]).unwrap();
        assert_eq!((bytes.as_slice(), ct.as_str()), (&b"MP3"[..], "audio/mpeg"));
        assert_eq!(srv.requests()[0].header("authorization"), Some("Bearer sk-live"));
        // ureq's own default (`redirect_auth_headers = Never`) still holds for the hops we make.
        let hops: Vec<String> = cdn.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(hops, vec!["/cdn/out.mp3".to_string(), "/cdn/final.mp3".to_string()], "relative Location resolved against the hop");
        assert!(cdn.requests().iter().all(|r| r.header("authorization").is_none()), "the key must not travel to the redirect target");
    }

    #[test]
    fn location_resolution() {
        assert_eq!(resolve_location("https://a.test/x/y.mp4?q=1", "https://b.test/z"), "https://b.test/z");
        assert_eq!(resolve_location("https://a.test/x/y.mp4?q=1", "//b.test/z"), "https://b.test/z");
        assert_eq!(resolve_location("https://a.test/x/y.mp4?q=1", "/z"), "https://a.test/z");
        assert_eq!(resolve_location("https://a.test/x/y.mp4?q=1", "z.mp4"), "https://a.test/x/z.mp4");
    }

    #[test]
    fn poll_until_done_or_timeout() {
        let mut n = 0;
        let v = poll(&Cancel::new(), Duration::from_millis(1), Duration::from_secs(5), || {
            n += 1;
            Ok((n == 3).then_some(n))
        })
        .unwrap();
        assert_eq!(v, 3);
        let e = poll::<()>(&Cancel::new(), Duration::from_millis(1), Duration::from_millis(5), || Ok(None)).unwrap_err();
        assert!(e.contains("timed out"));
    }
}
