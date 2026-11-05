//! Small blocking HTTP helpers for ops commands (update index, paste upload, OTLP,
//! secret managers) and a scripted fake server for their tests.

use std::io::Read;
use std::time::Duration;

pub fn agent(timeout: Duration) -> ureq::Agent {
    seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(timeout)).build().into()
}

/// (status, body) with the body capped at `limit` bytes.
pub fn request(method: &str, url: &str, headers: &[(&str, String)], body: Option<&[u8]>, limit: u64, timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let a = agent(timeout);
    let net = |e: ureq::Error| format!("{url}: {e}");
    let r = match (method, body) {
        ("GET", _) => {
            let mut rq = a.get(url);
            for (k, v) in headers {
                rq = rq.header(*k, v);
            }
            rq.call().map_err(net)?
        }
        ("DELETE", _) => {
            let mut rq = a.delete(url);
            for (k, v) in headers {
                rq = rq.header(*k, v);
            }
            rq.call().map_err(net)?
        }
        (m, b) => {
            let mut rq = match m {
                "PUT" => a.put(url),
                "PATCH" => a.patch(url),
                _ => a.post(url),
            };
            for (k, v) in headers {
                rq = rq.header(*k, v);
            }
            rq.send(b.unwrap_or(&[])).map_err(net)?
        }
    };
    let status = r.status().as_u16();
    let mut buf = Vec::new();
    r.into_body().into_reader().take(limit).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok((status, buf))
}

pub fn get_json(url: &str, headers: &[(&str, String)]) -> Result<serde_json::Value, String> {
    let (s, b) = request("GET", url, headers, None, 16 << 20, Duration::from_secs(30))?;
    if !(200..300).contains(&s) {
        return Err(format!("{url}: HTTP {s}: {}", String::from_utf8_lossy(&b).chars().take(300).collect::<String>()));
    }
    serde_json::from_slice(&b).map_err(|e| format!("{url}: bad JSON: {e}"))
}

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

    pub type Handler = Arc<dyn Fn(&Req) -> (u16, String, Vec<u8>) + Send + Sync>;

    /// Serve until the test ends; returns the base URL and the recorded requests.
    pub fn serve(h: Handler) -> (String, Arc<Mutex<Vec<Req>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log = Arc::new(Mutex::new(vec![]));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (h, log) = (h.clone(), log2.clone());
                std::thread::spawn(move || {
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let mut parts = line.split_whitespace();
                        let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
                        let mut headers = vec![];
                        let mut len = 0;
                        loop {
                            let mut hl = String::new();
                            r.read_line(&mut hl).unwrap();
                            let hl = hl.trim_end();
                            if hl.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = hl.split_once(':') {
                                if k.eq_ignore_ascii_case("content-length") {
                                    len = v.trim().parse().unwrap_or(0);
                                }
                                headers.push((k.to_lowercase(), v.trim().to_string()));
                            }
                        }
                        let mut body = vec![0; len];
                        r.read_exact(&mut body).unwrap();
                        let req = Req { method, path, headers, body };
                        let (status, ctype, out) = h(&req);
                        log.lock().unwrap().push(req);
                        let mut w = s.try_clone().unwrap();
                        let _ = write!(w, "HTTP/1.1 {status} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n\r\n", out.len());
                        let _ = w.write_all(&out);
                    }
                });
            }
        });
        (base, log)
    }
}
