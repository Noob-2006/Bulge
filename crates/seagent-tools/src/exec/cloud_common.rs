//! Shared plumbing for the cloud sandbox backends (Daytona, Vercel, Modal):
//! a retrying JSON HTTP client, a channel-fed `ExecChild`, the persisted
//! per-scope sandbox record, and small codecs (base64, tar, gzip, multipart)
//! the transports need without adding crates.

use seagent_core::exec::{ExecChild, ExitInfo};
use serde_json::Value;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::Duration;

/// HTTP statuses worth retrying (Hermes vercel `_TRANSIENT_STATUS_CODES`).
const TRANSIENT: &[u16] = &[408, 425, 429, 500, 502, 503, 504];
const ATTEMPTS: u32 = 3;
const MAX_BODY: u64 = 64 * 1024 * 1024;

/// A REST endpoint with fixed headers (auth) and transient-error retries.
#[derive(Clone)]
pub struct Api {
    pub base: String,
    pub headers: Vec<(String, String)>,
    /// Appended to every URL (`teamId=…` for Vercel).
    pub query: String,
    agent: ureq::Agent,
    /// Test hook: no sleep between retries.
    pub retry_delay: Duration,
}

impl Api {
    pub fn new(base: &str, headers: Vec<(String, String)>) -> Api {
        let agent = seagent_net::http::builder().http_status_as_error(false).timeout_connect(Some(Duration::from_secs(30))).timeout_global(Some(Duration::from_secs(3600))).build().into();
        Api { base: base.trim_end_matches('/').to_string(), headers, query: String::new(), agent, retry_delay: Duration::from_millis(100) }
    }

    pub fn url(&self, path: &str) -> String {
        let mut u = if path.starts_with("http://") || path.starts_with("https://") { path.to_string() } else { format!("{}{path}", self.base) };
        if !self.query.is_empty() {
            u.push(if u.contains('?') { '&' } else { '?' });
            u.push_str(&self.query);
        }
        u
    }

    /// One request; `body` is (content type, bytes). Returns (status, body bytes).
    pub fn raw(&self, method: &str, path: &str, body: Option<(&str, &[u8])>) -> Result<(u16, Vec<u8>), String> {
        let url = self.url(path);
        let mut last = String::new();
        for attempt in 1..=ATTEMPTS {
            match self.once(method, &url, body) {
                Ok((s, b)) if TRANSIENT.contains(&s) && attempt < ATTEMPTS => last = format!("HTTP {s}: {}", String::from_utf8_lossy(&b)),
                Ok(r) => return Ok(r),
                Err(e) if attempt < ATTEMPTS => last = e,
                Err(e) => return Err(e),
            }
            std::thread::sleep(self.retry_delay * attempt);
        }
        Err(last)
    }

    fn once(&self, method: &str, url: &str, body: Option<(&str, &[u8])>) -> Result<(u16, Vec<u8>), String> {
        macro_rules! hdrs {
            ($r:expr) => {{
                let mut r = $r;
                for (k, v) in &self.headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r
            }};
        }
        let res = match (method, body) {
            ("GET", _) => hdrs!(self.agent.get(url)).call(),
            ("DELETE", _) => hdrs!(self.agent.delete(url)).call(),
            ("POST", Some((ct, b))) => hdrs!(self.agent.post(url)).header("content-type", ct).send(b),
            ("POST", None) => hdrs!(self.agent.post(url)).send_empty(),
            ("PUT", Some((ct, b))) => hdrs!(self.agent.put(url)).header("content-type", ct).send(b),
            ("PATCH", Some((ct, b))) => hdrs!(self.agent.patch(url)).header("content-type", ct).send(b),
            (m, _) => return Err(format!("unsupported method {m}")),
        };
        let mut resp = res.map_err(|e| format!("{method} {url}: {e}"))?;
        let status = resp.status().as_u16();
        let mut raw = Vec::new();
        resp.body_mut().with_config().limit(MAX_BODY).reader().read_to_end(&mut raw).map_err(|e| format!("{method} {url}: reading body: {e}"))?;
        Ok((status, raw))
    }

    /// JSON request; non-2xx becomes `HTTP <status>: <body>`.
    pub fn json(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let bytes = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
        let (status, raw) = self.raw(method, path, bytes.as_deref().map(|b| ("application/json", b)))?;
        if !(200..300).contains(&status) {
            return Err(format!("{method} {path}: HTTP {status}: {}", String::from_utf8_lossy(&raw).chars().take(500).collect::<String>()));
        }
        if raw.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&raw).map_err(|e| format!("{method} {path}: bad JSON: {e}"))
    }

    /// Streaming GET: the body as a reader (logs that stay open until the command ends).
    pub fn stream(&self, path: &str) -> Result<Box<dyn Read + Send>, String> {
        let url = self.url(path);
        let mut r = self.agent.get(&url);
        for (k, v) in &self.headers {
            r = r.header(k.as_str(), v.as_str());
        }
        let resp = r.call().map_err(|e| format!("GET {url}: {e}"))?;
        let status = resp.status().as_u16();
        let reader = resp.into_body().into_reader();
        if !(200..300).contains(&status) {
            let mut raw = Vec::new();
            let _ = reader.take(4096).read_to_end(&mut raw);
            return Err(format!("GET {path}: HTTP {status}: {}", String::from_utf8_lossy(&raw)));
        }
        Ok(Box::new(reader))
    }
}

// ───────────── a child fed by a worker thread ─────────────

pub enum Ev {
    Out(Vec<u8>),
    Exit(ExitInfo),
}

pub type StdinFn = Box<dyn FnMut(&[u8]) -> io::Result<()> + Send>;
pub type KillFn = Box<dyn FnMut(bool) + Send>;

/// `ExecChild` whose output and exit arrive over a channel from a thread that
/// talks to the remote API. Senders must send every `Out` before `Exit`.
pub struct RemoteChild {
    rx: Receiver<Ev>,
    pending: Vec<u8>,
    exit: Option<ExitInfo>,
    stdin: Option<StdinFn>,
    close: Option<Box<dyn FnMut() + Send>>,
    killer: Option<KillFn>,
    /// Message for write_stdin when the transport has no stdin.
    no_stdin: &'static str,
}

impl RemoteChild {
    pub fn new(rx: Receiver<Ev>, stdin: Option<StdinFn>, close: Option<Box<dyn FnMut() + Send>>, killer: Option<KillFn>, no_stdin: &'static str) -> RemoteChild {
        RemoteChild { rx, pending: Vec::new(), exit: None, stdin, close, killer, no_stdin }
    }
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        n
    }
    fn absorb(&mut self, ev: Ev) {
        match ev {
            Ev::Out(b) => self.pending.extend_from_slice(&b),
            Ev::Exit(e) => self.exit = Some(e),
        }
    }
}

impl ExecChild for RemoteChild {
    fn pid(&self) -> Option<u32> {
        None
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if !self.pending.is_empty() {
            return Ok(self.take(buf));
        }
        loop {
            match self.rx.recv_timeout(timeout) {
                Ok(ev) => {
                    self.absorb(ev);
                    if !self.pending.is_empty() {
                        return Ok(self.take(buf));
                    }
                }
                Err(RecvTimeoutError::Timeout) => return Err(io::ErrorKind::TimedOut.into()),
                Err(RecvTimeoutError::Disconnected) => return Ok(0),
            }
        }
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        match self.stdin.as_mut() {
            Some(f) => f(data),
            None => Err(io::Error::new(io::ErrorKind::Unsupported, self.no_stdin)),
        }
    }
    fn close_stdin(&mut self) {
        self.stdin = None;
        if let Some(mut c) = self.close.take() {
            c();
        }
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        loop {
            match self.rx.try_recv() {
                Ok(ev) => self.absorb(ev),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.exit.is_none() {
                        // Worker died without a status (transport error was already reported as output).
                        self.exit = Some(ExitInfo { code: None, signal: None });
                    }
                    break;
                }
            }
        }
        Ok(self.exit)
    }
    fn kill(&mut self, force: bool) {
        if self.exit.is_none() {
            if let Some(k) = self.killer.as_mut() {
                k(force);
            }
        }
    }
}

// ───────────── persisted sandbox record ─────────────

/// `<home>/sandboxes/<backend>/<scope_key>.json`: the remote sandbox id (and
/// snapshot id) of a scope, so seagent restarts reuse the same sandbox.
pub struct Record {
    path: PathBuf,
}

impl Record {
    pub fn new(home: &Path, backend: &str, scope_key: &str) -> Record {
        Record { path: home.join("sandboxes").join(backend).join(format!("{}.json", crate::exec::sanitize(scope_key))) }
    }
    pub fn load(&self) -> Value {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
    }
    pub fn get(&self, k: &str) -> Option<String> {
        self.load().get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from)
    }
    pub fn set(&self, k: &str, v: Option<&str>) {
        let mut cur = self.load();
        if !cur.is_object() {
            cur = Value::Object(Default::default());
        }
        let o = cur.as_object_mut().unwrap();
        match v {
            Some(v) => {
                o.insert(k.into(), Value::String(v.into()));
            }
            None => {
                o.remove(k);
            }
        }
        if let Some(d) = self.path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = crate::util::atomic_write(&self.path, serde_json::to_string_pretty(&cur).unwrap_or_default().as_bytes());
    }
}

// ───────────── codecs ─────────────

pub fn b64(data: &[u8]) -> String {
    seagent_core::tool::base64_encode(data)
}

/// Standard base64 decode; whitespace ignored.
pub fn unb64(s: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            c if c.is_ascii_whitespace() => continue,
            c => return Err(format!("invalid base64 byte 0x{c:02x}")),
        } as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

/// gzip with stored (uncompressed) deflate blocks: valid for every decoder.
pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let chunks: Vec<&[u8]> = if data.is_empty() { vec![&[][..]] } else { data.chunks(65535).collect() };
    for (i, ch) in chunks.iter().enumerate() {
        out.push(if i + 1 == chunks.len() { 1 } else { 0 });
        let len = ch.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(ch);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// multipart/form-data with one file part; returns (content type, body).
pub fn multipart_file(field: &str, filename: &str, data: &[u8]) -> (String, Vec<u8>) {
    let boundary = format!("seagent{:016x}", crate::exec::sanitize(filename).len() as u64 ^ crc32(data) as u64 ^ 0x5eed_5eed_5eed);
    let mut b = Vec::new();
    b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n", filename.replace('"', "")).as_bytes());
    b.extend_from_slice(data);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), b)
}

/// Percent-encode a query value.
pub fn qenc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~/".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// `export K=V; ` lines for the request environment, credential names and
/// unsafe values dropped (they must not cross into a cloud sandbox).
pub fn env_prefix(env: &[(String, String)], passthrough: &[String]) -> String {
    let (kept, _) = crate::exec::sandbox::sanitize_forwarded(env, passthrough);
    kept.iter().filter(|(k, _)| !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')).map(|(k, v)| format!("export {k}={}\n", crate::exec::sh_quote(v))).collect()
}

/// Remote path for a host path under `host_root` (else the host path itself
/// when it is already a remote-looking absolute path).
pub fn map_under(host_root: &Path, remote_root: &str, host: &Path) -> String {
    match host.strip_prefix(host_root) {
        Ok(rel) if rel.as_os_str().is_empty() => remote_root.to_string(),
        Ok(rel) => format!("{}/{}", remote_root.trim_end_matches('/'), rel.display()),
        Err(_) => host.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_roundtrip() {
        for s in [&b""[..], b"a", b"ab", b"abc", b"hello world\x00\xff"] {
            assert_eq!(unb64(b64(s).as_bytes()).unwrap(), s);
        }
        assert_eq!(unb64(b"aGVs\nbG8=").unwrap(), b"hello");
        assert!(unb64(b"a*b").is_err());
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let g = gzip_stored(b"payload");
        assert_eq!(&g[..3], &[0x1f, 0x8b, 8]);
        assert_eq!(&g[g.len() - 4..], &7u32.to_le_bytes());
        let (ct, body) = multipart_file("file", "x.bin", b"DATA");
        assert!(ct.starts_with("multipart/form-data; boundary="));
        assert!(String::from_utf8_lossy(&body).contains("filename=\"x.bin\"") && body.windows(4).any(|w| w == b"DATA"));
        assert_eq!(qenc("/a b/c"), "/a%20b/c");
        assert_eq!(map_under(Path::new("/w"), "/r", Path::new("/w/x/y")), "/r/x/y");
        assert_eq!(map_under(Path::new("/w"), "/r", Path::new("/w")), "/r");
        let p = env_prefix(&[("A".into(), "1 2".into()), ("X_TOKEN".into(), "s".into()), ("bad name".into(), "v".into())], &[]);
        assert_eq!(p, "export A='1 2'\n");
    }

    #[test]
    fn record_persists() {
        let d = crate::testutil::tmpdir("cloudrec");
        let r = Record::new(&d, "daytona", "s-1");
        assert_eq!(r.get("id"), None);
        r.set("id", Some("abc"));
        assert_eq!(Record::new(&d, "daytona", "s-1").get("id").as_deref(), Some("abc"));
        r.set("id", None);
        assert_eq!(r.get("id"), None);
    }

    #[test]
    fn remote_child_orders_output_before_exit() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Ev::Out(b"hello ".to_vec())).unwrap();
        tx.send(Ev::Out(b"world".to_vec())).unwrap();
        tx.send(Ev::Exit(ExitInfo::code(3))).unwrap();
        drop(tx);
        let c = RemoteChild::new(rx, None, None, None, "no stdin here");
        let mut c: Box<dyn ExecChild> = Box::new(c);
        assert!(c.write_stdin(b"x").unwrap_err().to_string().contains("no stdin here"));
        let (st, out) = crate::exec::drain(c, Duration::from_secs(2)).unwrap();
        assert_eq!((st.code, out.as_slice()), (Some(3), &b"hello world"[..]));
    }
}

/// A tiny HTTP/1.1 server for backend tests: every request is recorded and
/// answered by the handler (keep-alive aware, Content-Length bodies only).
#[cfg(test)]
pub mod fake {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub struct Req {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl Req {
        pub fn header(&self, k: &str) -> Option<&str> {
            self.headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
        }
        pub fn json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).unwrap_or_default()
        }
    }

    pub type Handler = Arc<dyn Fn(&Req) -> (u16, Vec<u8>) + Send + Sync>;

    pub struct Server {
        pub url: String,
        pub log: Arc<Mutex<Vec<Req>>>,
    }

    impl Server {
        pub fn paths(&self) -> Vec<String> {
            self.log.lock().unwrap().iter().map(|r| format!("{} {}", r.method, r.path)).collect()
        }
        pub fn find(&self, pred: impl Fn(&Req) -> bool) -> Option<Req> {
            self.log.lock().unwrap().iter().find(|r| pred(r)).cloned()
        }
    }

    pub fn serve(h: Handler) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let log: Arc<Mutex<Vec<Req>>> = Default::default();
        let log2 = log.clone();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(conn) = conn else { break };
                let (h, log) = (h.clone(), log2.clone());
                std::thread::spawn(move || {
                    let mut w = conn.try_clone().unwrap();
                    let mut r = BufReader::new(conn);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let mut it = line.split_whitespace();
                        let (method, path) = (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string());
                        let mut headers = Vec::new();
                        loop {
                            let mut l = String::new();
                            if r.read_line(&mut l).unwrap_or(0) == 0 {
                                return;
                            }
                            let l = l.trim_end();
                            if l.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = l.split_once(':') {
                                headers.push((k.trim().to_string(), v.trim().to_string()));
                            }
                        }
                        let len = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0usize);
                        let mut body = vec![0; len];
                        if r.read_exact(&mut body).is_err() {
                            return;
                        }
                        let req = Req { method, path, headers, body };
                        let (status, out) = h(&req);
                        log.lock().unwrap().push(req);
                        let head = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", out.len());
                        if w.write_all(head.as_bytes()).and_then(|_| w.write_all(&out)).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Server { url, log }
    }

    pub fn ok(v: serde_json::Value) -> (u16, Vec<u8>) {
        (200, serde_json::to_vec(&v).unwrap())
    }
}

/// Fake CLIs for backend tests (ssh, singularity, openshell): each test writes a
/// `#!/bin/bash` stand-in into a temp dir and either puts that dir first on `PATH`
/// or points the backend's `binary` / `command` setting at it.
#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
pub mod fakecli {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    /// `PATH` is process-wide: tests that prepend a fake CLI take this lock.
    static PATH_LOCK: Mutex<()> = Mutex::new(());

    pub fn lock_path() -> MutexGuard<'static, ()> {
        PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(unix)]
    /// Write `dir/name` as an executable bash script.
    pub fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Put `dir` first on `PATH`; returns the previous value for [`restore_path`].
    pub fn prepend_path(dir: &Path) -> Option<OsString> {
        let old = std::env::var_os("PATH");
        let new = match &old {
            Some(p) => format!("{}:{}", dir.display(), p.to_string_lossy()),
            None => dir.display().to_string(),
        };
        std::env::set_var("PATH", new);
        old
    }

    pub fn restore_path(old: Option<OsString>) {
        match old {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
    }

    #[cfg(unix)]
    /// A stand-in `ssh` in `dir`: records its argv to `log`, answers `-V`, treats
    /// `-O …` as "close the master", fails for hosts containing `unreachable`, and
    /// otherwise runs the trailing remote script **locally** with `HOME` pointing
    /// at `remote_home` (so `~/…`, credential files and `$HOME` detect work).
    pub fn fake_ssh(dir: &Path, log: &Path, remote_home: &Path) -> PathBuf {
        let body = format!(
            r#"#!/bin/bash
printf '%s\n' "$*" >> {log}
for a in "$@"; do
    if [ "$a" = "-V" ]; then echo "OpenSSH_9.9p1 Fake, OpenSSL 3.0" >&2; exit 0; fi
done
prev=""
for a in "$@"; do
    if [ "$prev" = "-O" ]; then exit 0; fi
    prev="$a"
done
case "$*" in
    *unreachable*) echo "ssh: connect to host unreachable port 22: Connection refused" >&2; exit 255 ;;
esac
# Like real ssh: skip options, the first positional is the target, and every argument
# after it is joined with spaces into ONE command line for the remote shell (so a
# script passed as separate unquoted words breaks here exactly as it does over ssh).
args=("$@"); i=0; n=${{#args[@]}}
while [ $i -lt $n ]; do
    case "${{args[$i]}}" in
        -o|-p|-i|-O|-l|-S|-F|-J|-c|-E|-L|-R|-D|-W|-b|-e|-m|-Q|-w) i=$((i+2)) ;;
        -*) i=$((i+1)) ;;
        *) break ;;
    esac
done
cmd="${{args[*]:$((i+1))}}"
export HOME={home}
exec bash -c "$cmd"
"#,
            log = log.display(),
            home = remote_home.display()
        );
        script(dir, "ssh", &body)
    }
}

/// The plugin-provider path (`exec::register_provider`, the seam `seagent_plugin::exec`
/// bridges into): `[exec] backend = "<plugin name>"` must reach `build_backend`, build
/// the registered backend and run a command through it. The registry itself lives in
/// `exec/mod.rs`; this is the crate's test-support file, so the end-to-end proof lives here.
#[cfg(test)]
mod plugin_provider {
    use crate::exec::{register_provider, BackendCtx, ExecConfig, ExecEnv};
    use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
    use serde_json::Value;
    use std::io;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// The smallest provider a plugin can hand over: it reports its own id and runs
    /// commands through the local backend.
    struct PluginBackend;

    impl ExecBackend for PluginBackend {
        fn id(&self) -> &str {
            "plugin-acme"
        }
        fn describe(&self) -> String {
            "plugin-acme: registered by a plugin through exec::register_provider".into()
        }
        fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
            crate::exec::local::LocalBackend::new().spawn(req)
        }
    }

    #[test]
    fn config_selects_a_registered_provider_and_spawns() {
        let seen: Arc<Mutex<Vec<String>>> = Default::default();
        let s2 = seen.clone();
        register_provider(
            "plugin-acme",
            Arc::new(move |v: &Value, c: &BackendCtx| {
                s2.lock().unwrap().push(format!("config_null={} scope={} sandboxed={} ws={}", v.is_null(), c.scope_key, c.sandboxed, c.workspace.display()));
                Ok(Arc::new(PluginBackend) as Arc<dyn ExecBackend>)
            }),
        );
        // The name is only accepted after registration (`ExecConfig::validate`).
        assert!(ExecConfig::parse(&serde_json::json!({"backend": "plugin-acme"})).is_ok());
        let ws = crate::testutil::tmpdir("plugws");
        let home = crate::testutil::tmpdir("plughome");
        let env = ExecEnv::new(ExecConfig { backend: "plugin-acme".into(), ..Default::default() });
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        let b = env.backend("s1", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "plugin-acme");
        assert!(b.describe().contains("register_provider"));
        let (st, out) = crate::exec::run_capture(b.as_ref(), "echo from-plugin", None, Duration::from_secs(20)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("from-plugin"), "{}", String::from_utf8_lossy(&out));
        // The provider was called once for this session, with the session's workspace/scope.
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].contains("ws=") && seen[0].contains("scope=host-s1"), "{seen:?}");
        // Cached: a second call for the same session does not rebuild the backend.
        let _ = env.backend("s1", &ws, &home, &secrets, false).unwrap();
        assert_eq!(seen.len(), 1);
        // Unknown names still fail with the config error, not a panic.
        assert!(ExecConfig::parse(&serde_json::json!({"backend": "not-registered"})).is_err());
        let _ = Path::new("/");
    }
}
