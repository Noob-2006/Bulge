//! Result caches (Hermes `tools/web_result_cache.py`, OpenClaw `web-shared.ts`).
//! * Search memo — in memory, per process, single-flighted: concurrent identical queries
//!   share one paid request. Counts bucket to 10/20/50/100 so near-identical calls share.
//! * Extract cache — on disk under `<home>/cache/web` with a JSON index (500 newest
//!   entries), keyed by URL + format + provider, so CLI, daemon and sub-agents share it.
//! * Fetch cache — in memory, 100 entries (OpenClaw `FETCH_CACHE`).
//!   Hits sit after every safety check: they skip only the network call.

use super::ssrf::{is_local_dev_url, parse_url};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LIMIT_BUCKETS: [usize; 4] = [10, 20, 50, 100];
const INDEX_FILE: &str = "extract-index.json";
const INDEX_MAX: usize = 500;
/// Pages longer than the stored-copy ceiling are not cached (a capped copy would lose the tail).
pub const MAX_STORED_TEXT_CHARS: usize = 2_000_000;

pub fn bucket_limit(n: usize) -> usize {
    LIMIT_BUCKETS.iter().copied().find(|b| n <= *b).unwrap_or(100)
}

pub fn normalize_query(q: &str) -> String {
    q.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

pub fn digest(s: &str) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(s.as_bytes()))
}

/// Filesystem-safe host slug for cache file names (`page` when hostless).
pub fn host_slug(url: &str) -> String {
    let h = parse_url(url).map(|u| u.host.replace(':', "_")).unwrap_or_else(|_| "page".into());
    let s: String = h.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' }).take(60).collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "page".into()
    } else {
        s
    }
}

// ── search memo ───────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Memo {
    store: Mutex<HashMap<String, (Instant, Value)>>,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl Memo {
    pub fn get(&self, key: &str) -> Option<Value> {
        let mut s = self.store.lock().unwrap();
        match s.get(key) {
            Some((exp, v)) if Instant::now() < *exp => Some(v.clone()),
            Some(_) => {
                s.remove(key);
                None
            }
            None => None,
        }
    }
    pub fn put(&self, key: &str, v: Value, ttl: Duration, max: usize) {
        let mut s = self.store.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, (exp, _)| now < *exp);
        if s.len() >= max {
            if let Some(oldest) = s.iter().min_by_key(|(_, (e, _))| *e).map(|(k, _)| k.clone()) {
                s.remove(&oldest);
            }
        }
        s.insert(key.to_string(), (now + ttl, v));
    }
    /// Per-key lock held around miss → paid request → store. Held locks are never evicted.
    pub fn flight(&self, key: &str) -> Arc<Mutex<()>> {
        let mut l = self.locks.lock().unwrap();
        if l.len() > 256 {
            l.retain(|_, m| Arc::strong_count(m) > 1);
        }
        l.entry(key.to_string()).or_default().clone()
    }
    pub fn clear(&self) {
        self.store.lock().unwrap().clear();
        self.locks.lock().unwrap().clear();
    }
}

pub fn search_memo() -> &'static Memo {
    static M: OnceLock<Memo> = OnceLock::new();
    M.get_or_init(Memo::default)
}

pub fn fetch_memo() -> &'static Memo {
    static M: OnceLock<Memo> = OnceLock::new();
    M.get_or_init(Memo::default)
}

// ── extract cache (disk) ───────────────────────────────────────────────────────

fn host_matches(host: &str, pat: &str) -> bool {
    let p = pat.trim().trim_matches('.').to_ascii_lowercase();
    let p = p.strip_prefix("*.").unwrap_or(&p);
    !p.is_empty() && (host == p || host.ends_with(&format!(".{p}")))
}

/// Cache gate: enabled, not a local-dev host, not in `web.cache_exempt_hosts`.
pub fn cacheable(cfg: &super::WebConfig, url: &str) -> bool {
    if !cfg.cache_enabled || is_local_dev_url(url) {
        return false;
    }
    let host = parse_url(url).map(|u| u.host).unwrap_or_default();
    !cfg.cache_exempt_hosts.iter().any(|p| host_matches(&host, p))
}

pub struct DiskCache {
    pub dir: PathBuf,
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn index_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

impl DiskCache {
    pub fn new(home: &Path) -> DiskCache {
        DiskCache { dir: home.join("cache").join("web") }
    }
    fn key(url: &str, format: &str, provider: &str) -> String {
        digest(&format!("{url}\n{format}\n{provider}"))[..16].to_string()
    }
    fn load(&self) -> serde_json::Map<String, Value> {
        std::fs::read_to_string(self.dir.join(INDEX_FILE)).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v.as_object().cloned()).unwrap_or_default()
    }
    /// `(title, content)` of a fresh entry.
    pub fn get(&self, url: &str, format: &str, provider: &str, ttl: u64) -> Option<(String, String)> {
        let entry = {
            let _g = index_lock().lock().unwrap();
            self.load().get(&Self::key(url, format, provider)).cloned()?
        };
        let at = entry.get("fetched_at").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if now_secs() - at >= ttl as f64 {
            return None;
        }
        let file = PathBuf::from(entry.get("file")?.as_str()?);
        // The index is plain JSON: never follow a tampered entry outside the cache dir.
        let root = self.dir.canonicalize().ok()?;
        if !file.canonicalize().ok()?.starts_with(&root) {
            return None;
        }
        let content = std::fs::read_to_string(&file).ok()?;
        Some((entry.get("title").and_then(|t| t.as_str()).unwrap_or("").to_string(), content))
    }
    pub fn put(&self, url: &str, format: &str, provider: &str, title: &str, content: &str) {
        if content.is_empty() || content.chars().count() > MAX_STORED_TEXT_CHARS || std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let k = Self::key(url, format, provider);
        let file = self.dir.join(format!("{}-{k}.cache.md", host_slug(url)));
        if write_no_follow(&file, content).is_err() {
            return;
        }
        let _g = index_lock().lock().unwrap();
        let mut idx = self.load();
        idx.insert(k, json!({"url": url, "file": file.to_string_lossy(), "title": title, "fetched_at": now_secs()}));
        if idx.len() > INDEX_MAX {
            let mut v: Vec<(String, Value)> = idx.into_iter().collect();
            v.sort_by(|a, b| b.1["fetched_at"].as_f64().unwrap_or(0.0).partial_cmp(&a.1["fetched_at"].as_f64().unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
            v.truncate(INDEX_MAX);
            idx = v.into_iter().collect();
        }
        let _ = crate::util::atomic_write(&self.dir.join(INDEX_FILE), Value::Object(idx).to_string().as_bytes());
    }
}

/// Write without following a symlink planted at a predictable name (lstat-unlink + create).
pub fn write_no_follow(path: &Path, content: &str) -> std::io::Result<()> {
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if m.file_type().is_symlink() || m.is_file() {
            std::fs::remove_file(path)?;
        }
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(content.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::WebConfig;

    #[test]
    fn buckets_and_keys() {
        assert_eq!((bucket_limit(1), bucket_limit(10), bucket_limit(11), bucket_limit(60), bucket_limit(500)), (10, 10, 20, 100, 100));
        assert_eq!(normalize_query("  Rust   LANG "), "rust lang");
        assert_eq!(host_slug("https://a.b.com:8443/x"), "a.b.com");
        assert_eq!(host_slug("nonsense"), "page");
    }

    #[test]
    fn memo_ttl_and_flight() {
        let m = Memo::default();
        m.put("k", json!(1), Duration::from_secs(60), 10);
        assert_eq!(m.get("k"), Some(json!(1)));
        m.put("old", json!(2), Duration::from_millis(0), 10);
        assert_eq!(m.get("old"), None);
        for i in 0..5 {
            m.put(&format!("n{i}"), json!(i), Duration::from_secs(60 + i), 3);
        }
        assert!(m.store.lock().unwrap().len() <= 3);
        let a = m.flight("x");
        let b = m.flight("x");
        assert!(Arc::ptr_eq(&a, &b));
        m.clear();
        assert_eq!(m.get("k"), None);
    }

    #[test]
    fn disk_cache_roundtrip_and_gates() {
        let home = crate::testutil::tmpdir("webcache");
        let d = DiskCache::new(&home);
        d.put("https://ex.com/a", "markdown", "local", "T", "body");
        assert_eq!(d.get("https://ex.com/a", "markdown", "local", 60), Some(("T".into(), "body".into())));
        assert_eq!(d.get("https://ex.com/a", "markdown", "exa", 60), None, "provider is part of the key");
        assert_eq!(d.get("https://ex.com/a", "markdown", "local", 0), None, "expired");
        // A tampered index entry pointing outside the cache dir is ignored.
        let outside = home.join("secret.txt");
        std::fs::write(&outside, "x").unwrap();
        let mut idx = d.load();
        let k = DiskCache::key("https://ex.com/a", "markdown", "local");
        idx.get_mut(&k).unwrap()["file"] = json!(outside.to_string_lossy());
        std::fs::write(d.dir.join(INDEX_FILE), Value::Object(idx).to_string()).unwrap();
        assert_eq!(d.get("https://ex.com/a", "markdown", "local", 60), None);
        let mut cfg = WebConfig::default();
        assert!(cacheable(&cfg, "https://example.com/") && !cacheable(&cfg, "http://localhost:3000/") && !cacheable(&cfg, "http://192.168.1.2/"));
        cfg.cache_exempt_hosts = vec!["*.mysite.dev".into()];
        assert!(!cacheable(&cfg, "https://preview.mysite.dev/x") && !cacheable(&cfg, "https://mysite.dev/"));
        cfg.cache_enabled = false;
        assert!(!cacheable(&cfg, "https://example.com/"));
    }

    #[cfg(unix)]
    #[test]
    fn write_refuses_to_follow_symlinks() {
        let d = crate::testutil::tmpdir("webcache-ln");
        let target = d.join("target");
        std::fs::write(&target, "orig").unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_no_follow(&link, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "orig");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "new");
    }
}
