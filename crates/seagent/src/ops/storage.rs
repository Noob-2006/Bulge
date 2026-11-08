//! `seagent storage` (OpenClaw `openclaw storage`, `src/storage/*`): named storage
//! locations for backups/exports, with an initialization marker and optional
//! encryption.
//!
//! Locations live in `<config>/storage.toml`:
//!
//! ```toml
//! [locations.offsite]
//! provider = "filesystem"
//! path = "/mnt/usb/seagent"                       # absolute, must exist for `init`
//! passphrase = "{{secret:STORAGE_PASSPHRASE}}" # optional → encrypted objects
//! ```
//!
//! `init <name>` writes `openclaw-storage.json` (format-compatible marker: version,
//! locationId, createdAt, encryption none | scrypt N=32768 r=8 p=1 + HMAC key check),
//! or verifies an existing marker and key. `test <name>` writes, reads back, verifies
//! and deletes 256 random bytes. `list` probes every location (ok / unavailable /
//! uninitialized / wrong-key / error, with free/total bytes). Encrypted objects use the
//! upstream `OCSTOR1` framing: HKDF-SHA256 per-object key, AES-256-GCM over 1 MiB
//! segments with the header as AAD and a last-segment flag in the nonce.
//! Provider errors are never echoed raw (they may carry credentials).

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["storage"];
pub const VALUE_FLAGS: &[&str] = &["passphrase-secret"];
pub const BOOL_FLAGS: &[&str] = &[];

pub const MARKER_KEY: &str = "openclaw-storage.json";
const KEY_CHECK: &[u8] = b"openclaw-storage key check v1";
const MAGIC: &[u8] = b"OCSTOR1\n";
const SEGMENT: usize = 1 << 20;
const TAG: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocationConfig {
    #[serde(default = "d_provider")]
    pub provider: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}
fn d_provider() -> String {
    "filesystem".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageFile {
    #[serde(default)]
    pub locations: BTreeMap<String, LocationConfig>,
}

pub fn config_path(paths: &Paths) -> PathBuf {
    paths.config_dir.join("storage.toml")
}

pub fn load(paths: &Paths) -> Result<StorageFile, String> {
    match std::fs::read_to_string(config_path(paths)) {
        Ok(t) => toml::from_str(&t).map_err(|e| format!("{}: {}", config_path(paths).display(), e.message())),
        Err(_) => Ok(StorageFile::default()),
    }
}

pub fn save(paths: &Paths, f: &StorageFile) -> Result<(), String> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    seagent_kernel::util::atomic_write(&config_path(paths), toml::to_string_pretty(f).map_err(|e| e.to_string())?.as_bytes()).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct StorageError {
    /// unavailable | uninitialized | wrong-key | error
    pub state: &'static str,
    pub message: String,
}

impl StorageError {
    fn new(state: &'static str, m: impl Into<String>) -> StorageError {
        StorageError { state, message: m.into() }
    }
}

impl From<StorageError> for String {
    fn from(e: StorageError) -> String {
        e.message
    }
}

pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty() && b.len() <= 63 && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub fn validate_key(key: &str) -> Result<(), String> {
    let ok = key.len() <= 512 && key.split('/').all(|s| !s.is_empty() && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
    if ok {
        Ok(())
    } else {
        Err("Storage keys must contain nonempty /-separated letters, digits, dots, underscores or hyphens, without . or .. segments, and be at most 512 bytes.".into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Marker {
    pub version: u32,
    #[serde(rename = "locationId")]
    pub location_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    pub encryption: Value,
}

fn uuid4() -> String {
    let mut b = seagent_net::crypto::random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = seagent_net::crypto::hex(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn derive_master(pass: &str, salt: &[u8]) -> Vec<u8> {
    seagent_channel::dave::scrypt::scrypt(pass.as_bytes(), salt, 32768, 8, 1, 32)
}

pub fn create_marker(pass: Option<&str>) -> Marker {
    let encryption = match pass {
        None => json!("none"),
        Some(p) => {
            let salt = seagent_net::crypto::random_bytes(16);
            let key = derive_master(p, &salt);
            json!({"kdf": "scrypt", "salt": seagent_net::crypto::b64(&salt), "N": 32768, "r": 8, "p": 1, "keyCheck": seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha256(&key, KEY_CHECK))})
        }
    };
    Marker { version: 1, location_id: uuid4(), created_at: seagent_kernel::event::now_ms(), encryption }
}

/// Check the passphrase against the marker → master key (None = unencrypted).
pub fn verify_marker(name: &str, m: &Marker, pass: Option<&str>) -> Result<Option<Vec<u8>>, StorageError> {
    if m.version != 1 {
        return Err(StorageError::new("error", "Invalid storage location marker."));
    }
    if m.encryption == json!("none") {
        if pass.is_some() {
            return Err(StorageError::new("wrong-key", format!("Storage location \"{name}\" was initialized without encryption; restore its original encryption configuration.")));
        }
        return Ok(None);
    }
    let e = &m.encryption;
    if e["kdf"] != "scrypt" || e["N"] != 32768 || e["r"] != 8 || e["p"] != 1 {
        return Err(StorageError::new("error", "Invalid storage location marker."));
    }
    let Some(pass) = pass else {
        return Err(StorageError::new("wrong-key", format!("Storage location \"{name}\" requires its original encryption passphrase.")));
    };
    let salt = e["salt"].as_str().and_then(seagent_net::crypto::b64_decode).filter(|s| s.len() == 16).ok_or_else(|| StorageError::new("error", "Invalid storage location marker."))?;
    let want = e["keyCheck"].as_str().and_then(seagent_net::crypto::b64_decode).ok_or_else(|| StorageError::new("error", "Invalid storage location marker."))?;
    let key = derive_master(pass, &salt);
    if !seagent_net::crypto::ct_eq(&want, &seagent_net::crypto::hmac_sha256(&key, KEY_CHECK)) {
        return Err(StorageError::new("wrong-key", format!("Wrong encryption passphrase for storage location \"{name}\".")));
    }
    Ok(Some(key))
}

fn header(salt: &[u8], prefix: &[u8]) -> Vec<u8> {
    let j = json!({"v": 1, "objSalt": seagent_net::crypto::b64(salt), "noncePrefix": seagent_net::crypto::b64(prefix), "segmentBytes": SEGMENT}).to_string();
    let mut h = MAGIC.to_vec();
    h.extend_from_slice(&(j.len() as u32).to_be_bytes());
    h.extend_from_slice(j.as_bytes());
    h
}

fn nonce(prefix: &[u8], index: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&index.to_be_bytes());
    n[11] = u8::from(last);
    n
}

fn object_key(master: &[u8], salt: &[u8]) -> ring::aead::LessSafeKey {
    let k = seagent_channel::olm::hkdf(salt, master, b"openclaw-storage v1 object", 32);
    ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &k).expect("aes key"))
}

/// `OCSTOR1` framing: header, then AES-256-GCM segments (an exact multiple ends with an empty final segment).
pub fn encrypt(plain: &[u8], master: &[u8]) -> Vec<u8> {
    let salt = seagent_net::crypto::random_bytes(32);
    let prefix = seagent_net::crypto::random_bytes(7);
    let h = header(&salt, &prefix);
    let key = object_key(master, &salt);
    let mut out = h.clone();
    let mut i = 0u32;
    let mut off = 0;
    loop {
        let end = (off + SEGMENT).min(plain.len());
        let last = end - off < SEGMENT;
        let mut buf = plain[off..end].to_vec();
        key.seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce(&prefix, i, last)), ring::aead::Aad::from(&h[..]), &mut buf).expect("seal");
        out.extend_from_slice(&buf);
        if last {
            return out;
        }
        off = end;
        i += 1;
    }
}

pub fn decrypt(data: &[u8], master: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < MAGIC.len() + 4 || &data[..MAGIC.len()] != MAGIC {
        return Err("Invalid storage encryption magic.".into());
    }
    let len = u32::from_be_bytes(data[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap()) as usize;
    if len == 0 || len > 1024 || data.len() < MAGIC.len() + 4 + len {
        return Err("Invalid storage encryption header length.".into());
    }
    let hlen = MAGIC.len() + 4 + len;
    let h = &data[..hlen];
    let v: Value = serde_json::from_slice(&h[MAGIC.len() + 4..]).map_err(|_| "Unsupported storage encryption header.")?;
    if v["v"] != 1 || v["segmentBytes"] != SEGMENT {
        return Err("Unsupported storage encryption header.".into());
    }
    let salt = v["objSalt"].as_str().and_then(seagent_net::crypto::b64_decode).filter(|s| s.len() == 32).ok_or("Invalid storage encryption header.")?;
    let prefix = v["noncePrefix"].as_str().and_then(seagent_net::crypto::b64_decode).filter(|s| s.len() == 7).ok_or("Invalid storage encryption header.")?;
    let key = object_key(master, &salt);
    let mut out = vec![];
    let mut rest = &data[hlen..];
    let mut i = 0u32;
    loop {
        let take = rest.len().min(SEGMENT + TAG);
        if take < TAG {
            return Err("Truncated storage object: missing final segment.".into());
        }
        let last = take < SEGMENT + TAG;
        let mut seg = rest[..take].to_vec();
        let p = key.open_in_place(ring::aead::Nonce::assume_unique_for_key(nonce(&prefix, i, last)), ring::aead::Aad::from(h), &mut seg).map_err(|_| "Storage object failed authentication (wrong key or corrupted data).")?;
        out.extend_from_slice(p);
        rest = &rest[take..];
        if last {
            if !rest.is_empty() {
                return Err("Storage object has trailing data.".into());
            }
            return Ok(out);
        }
        i += 1;
    }
}

/// An opened (initialized, key-verified) filesystem location.
pub struct Location {
    pub name: String,
    pub root: PathBuf,
    pub marker: Marker,
    key: Option<Vec<u8>>,
}

fn check_settings(name: &str, c: &LocationConfig) -> Result<PathBuf, StorageError> {
    if !valid_name(name) {
        return Err(StorageError::new("error", "Invalid storage location name."));
    }
    if c.provider != "filesystem" {
        return Err(StorageError::new("error", format!("Storage provider `{}` is not available (seagent ships the filesystem provider).", c.provider)));
    }
    if !Path::new(&c.path).is_absolute() {
        return Err(StorageError::new("error", "Filesystem storage settings.path must be an absolute directory path."));
    }
    let p = PathBuf::from(&c.path);
    if !p.is_dir() {
        return Err(StorageError::new("unavailable", "Storage directory is unavailable. Reconnect the disk and check the configured path; storage init requires an existing directory."));
    }
    Ok(p)
}

fn read_marker(root: &Path) -> Result<Option<Marker>, StorageError> {
    match std::fs::read(root.join(MARKER_KEY)) {
        Err(_) => Ok(None),
        Ok(b) if b.len() > 4096 => Err(StorageError::new("error", "Storage marker exceeds 4096 bytes.")),
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|_| StorageError::new("error", "Invalid storage location marker.")),
    }
}

impl Location {
    pub fn init(name: &str, c: &LocationConfig, pass: Option<&str>) -> Result<Location, StorageError> {
        let root = check_settings(name, c)?;
        let marker = match read_marker(&root)? {
            Some(m) => m,
            None => {
                let m = create_marker(pass);
                seagent_kernel::util::atomic_write(&root.join(MARKER_KEY), serde_json::to_string(&m).unwrap().as_bytes()).map_err(|_| StorageError::new("error", "Storage could not be accessed. Check its provider settings, credentials, and connection."))?;
                m
            }
        };
        let key = verify_marker(name, &marker, pass)?;
        Ok(Location { name: name.into(), root, marker, key })
    }

    pub fn open(name: &str, c: &LocationConfig, pass: Option<&str>) -> Result<Location, StorageError> {
        let root = check_settings(name, c)?;
        let marker = read_marker(&root)?.ok_or_else(|| StorageError::new("uninitialized", format!("Storage location \"{name}\" ({}) has no initialization marker. If this is a new location, run `seagent storage init {name}`; otherwise reconnect the disk or check the path.", c.path)))?;
        let key = verify_marker(name, &marker, pass)?;
        Ok(Location { name: name.into(), root, marker, key })
    }

    pub fn encrypted(&self) -> bool {
        self.key.is_some()
    }

    fn file(&self, key: &str) -> Result<PathBuf, String> {
        validate_key(key)?;
        if key == MARKER_KEY {
            return Err("The storage marker is reserved for the storage owner.".into());
        }
        Ok(self.root.join(key))
    }

    pub fn put(&self, key: &str, data: &[u8]) -> Result<usize, String> {
        let f = self.file(key)?;
        if let Some(p) = f.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let body = match &self.key {
            Some(k) => encrypt(data, k),
            None => data.to_vec(),
        };
        seagent_kernel::util::atomic_write(&f, &body).map_err(|e| e.to_string())?;
        Ok(body.len())
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let f = self.file(key)?;
        let Ok(b) = std::fs::read(&f) else { return Ok(None) };
        match &self.key {
            Some(k) => decrypt(&b, k).map(Some),
            None => Ok(Some(b)),
        }
    }

    pub fn delete(&self, key: &str) -> Result<(), String> {
        let f = self.file(key)?;
        match std::fs::remove_file(&f) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn describe(&self) -> Value {
        json!({"name": self.name, "provider": "filesystem", "displayTarget": self.root, "locationId": self.marker.location_id, "encrypted": self.encrypted()})
    }

    /// Write, read back, verify and delete a random probe object.
    pub fn self_test(&self) -> Result<usize, String> {
        let key = format!(".openclaw-probe-{}", uuid4());
        let payload = seagent_net::crypto::random_bytes(256);
        self.put(&key, &payload)?;
        let back = self.get(&key);
        self.delete(&key)?;
        match back? {
            None => Err(format!("Storage test for \"{}\" failed: the written object is missing.", self.name)),
            Some(b) if b.len() < payload.len() => Err(format!("Storage test for \"{}\" failed: read-back bytes are truncated.", self.name)),
            Some(b) if b != payload => Err(format!("Storage test for \"{}\" failed: read-back bytes differ.", self.name)),
            Some(_) => Ok(payload.len()),
        }
    }
}

/// (available, total) bytes (`GetDiskFreeSpaceExW` through `platform::sysinfo`).
#[cfg(not(unix))]
fn space(p: &Path) -> Option<(u64, u64)> {
    seagent_core::platform::sysinfo::disk_space(p).ok().map(|d| (d.available, d.total))
}

#[cfg(unix)]
fn space(p: &Path) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid NUL-terminated path and an out-pointer to a zeroed statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some((s.f_bavail as u64 * s.f_frsize as u64, s.f_blocks as u64 * s.f_frsize as u64))
}

pub fn probe(name: &str, c: &LocationConfig, pass: Option<&str>) -> Value {
    let mut v = json!({"name": name, "provider": c.provider, "displayTarget": c.path, "encrypted": c.passphrase.is_some()});
    match Location::open(name, c, pass) {
        Ok(l) => {
            v["state"] = json!("ok");
            v["locationId"] = json!(l.marker.location_id);
            if let Some((free, total)) = space(&l.root) {
                v["freeBytes"] = json!(free);
                v["totalBytes"] = json!(total);
            }
        }
        Err(e) => {
            v["state"] = json!(e.state);
            v["message"] = json!(e.message);
        }
    }
    v
}

fn passphrase(c: &LocationConfig, subst: &dyn Fn(&str) -> String) -> Option<String> {
    c.passphrase.as_deref().map(subst).filter(|p| !p.is_empty() && !p.contains("{{secret:"))
}

fn location<'a>(f: &'a StorageFile, name: &str) -> Result<&'a LocationConfig, String> {
    if !valid_name(name) {
        return Err("Invalid storage location name.".into());
    }
    f.locations.get(name).ok_or_else(|| format!("Storage location \"{name}\" is not configured (add it with `seagent storage add {name} --path /abs/dir`)."))
}

/// One `seagent storage …` invocation → output.
pub fn run(paths: &Paths, a: &Args, subst: &dyn Fn(&str) -> String) -> Result<String, String> {
    let mut f = load(paths)?;
    let js = a.flag("json");
    Ok(match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let locs: Vec<Value> = f.locations.iter().map(|(n, c)| probe(n, c, passphrase(c, subst).as_deref())).collect();
            if js {
                return Ok(json!({"locations": locs}).to_string());
            }
            if locs.is_empty() {
                return Ok("No storage locations configured. Add one with `seagent storage add <name> --path /abs/dir`.".into());
            }
            locs.iter()
                .map(|l| format!("{} ({}): {} — {}{}", l["name"].as_str().unwrap_or(""), l["provider"].as_str().unwrap_or(""), l["state"].as_str().unwrap_or(""), l["displayTarget"].as_str().unwrap_or(""), l["message"].as_str().map(|m| format!("\n  {m}")).unwrap_or_default()))
                .collect::<Vec<_>>()
                .join("\n")
        }
        "init" => {
            let name = a.need(1, "name")?;
            let c = location(&f, name)?;
            let l = Location::init(name, c, passphrase(c, subst).as_deref())?;
            if js {
                let mut d = l.describe();
                d["state"] = json!("ok");
                d.to_string()
            } else {
                format!("Storage location {name} initialized: {}{}", l.root.display(), if l.encrypted() { " (encrypted)" } else { "" })
            }
        }
        "test" => {
            let name = a.need(1, "name")?;
            let c = location(&f, name)?;
            let l = Location::open(name, c, passphrase(c, subst).as_deref())?;
            let n = l.self_test()?;
            if js {
                let mut d = l.describe();
                d["state"] = json!("ok");
                d["sizeBytes"] = json!(n);
                d.to_string()
            } else {
                format!("Storage location {name}: wrote, read, verified, and deleted {n} bytes.")
            }
        }
        "add" => {
            let name = a.need(1, "name")?;
            if !valid_name(name) {
                return Err("Invalid storage location name (1-63 lowercase letters, digits, hyphens).".into());
            }
            let path = a.val("path").ok_or("--path /absolute/dir is required")?;
            if !Path::new(path).is_absolute() {
                return Err("Filesystem storage settings.path must be an absolute directory path.".into());
            }
            let pass = a.val("passphrase-secret").map(|s| format!("{{{{secret:{s}}}}}"));
            f.locations.insert(name.into(), LocationConfig { provider: "filesystem".into(), path: path.into(), passphrase: pass });
            save(paths, &f)?;
            format!("added storage location {name} → {path}; run `seagent storage init {name}`")
        }
        "rm" | "remove" => {
            let name = a.need(1, "name")?;
            if f.locations.remove(name).is_none() {
                return Err(format!("Storage location \"{name}\" is not configured."));
            }
            save(paths, &f)?;
            format!("removed storage location {name} (its files were not touched)")
        }
        other => return Err(format!("unknown `storage {other}` (list | init <name> | test <name> | add <name> --path DIR [--passphrase-secret NAME] | rm <name>)")),
    })
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "storage" {
        return None;
    }
    Some((|| -> R {
        let paths = Paths::from_env();
        let vault = crate::load_vault(&paths)?;
        let out = run(&paths, a, &|s: &str| vault.substitute(s))?;
        println!("{out}");
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn encryption_roundtrip_and_tamper() {
        let k = vec![7u8; 32];
        for n in [0, 5, SEGMENT, SEGMENT + 3] {
            let p: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let c = encrypt(&p, &k);
            assert!(c.starts_with(MAGIC));
            assert_eq!(decrypt(&c, &k).unwrap(), p, "len {n}");
        }
        let mut c = encrypt(b"hello", &k);
        let last = c.len() - 1;
        c[last] ^= 1;
        assert!(decrypt(&c, &k).unwrap_err().contains("authentication"));
        assert!(decrypt(&encrypt(b"x", &k), &[8u8; 32]).is_err());
        // truncating a full segment's final empty segment is detected
        let p = vec![1u8; SEGMENT];
        let c = encrypt(&p, &k);
        assert!(decrypt(&c[..c.len() - TAG], &k).is_err());
    }

    #[test]
    fn markers_keys_and_states() {
        let m = create_marker(Some("pw"));
        assert!(verify_marker("x", &m, Some("pw")).unwrap().is_some());
        assert_eq!(verify_marker("x", &m, Some("nope")).unwrap_err().state, "wrong-key");
        assert_eq!(verify_marker("x", &m, None).unwrap_err().state, "wrong-key");
        let plain = create_marker(None);
        assert_eq!(verify_marker("x", &plain, Some("pw")).unwrap_err().state, "wrong-key");
        assert!(validate_key("a/b.c_d-1").is_ok() && validate_key("a/../b").is_err() && validate_key("/abs").is_err() && validate_key("a//b").is_err());
        assert!(valid_name("off-site1") && !valid_name("Bad") && !valid_name("-x"));
    }

    #[test]
    fn cli_add_list_init_test() {
        let kit = crate::testkit::kit();
        let dir = kit.ws.join("vol");
        let subst = |s: &str| s.replace("{{secret:SP}}", "hunter2");
        let r = |v: &[&str]| run(&kit.paths, &args(v), &subst);
        assert!(r(&["list"]).unwrap().contains("No storage locations"));
        r(&["add", "plain", "--path", dir.to_str().unwrap()]).unwrap();
        assert!(r(&["list"]).unwrap().contains("unavailable"), "missing dir");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(r(&["list"]).unwrap().contains("uninitialized"));
        assert!(r(&["test", "plain"]).unwrap_err().contains("seagent storage init plain"));
        assert!(r(&["init", "plain"]).unwrap().contains("initialized"));
        assert!(r(&["init", "plain"]).unwrap().contains("initialized"), "re-init verifies the existing marker");
        assert!(r(&["test", "plain"]).unwrap().contains("wrote, read, verified, and deleted 256 bytes"));
        let v: Value = serde_json::from_str(&r(&["list", "--json"]).unwrap()).unwrap();
        assert_eq!(v["locations"][0]["state"], "ok");
        assert!(v["locations"][0]["totalBytes"].as_u64().unwrap() > 0);

        let edir = kit.ws.join("enc");
        std::fs::create_dir_all(&edir).unwrap();
        r(&["add", "secure", "--path", edir.to_str().unwrap(), "--passphrase-secret", "SP"]).unwrap();
        r(&["init", "secure"]).unwrap();
        assert!(r(&["test", "secure", "--json"]).unwrap().contains("\"encrypted\":true"));
        let f = load(&kit.paths).unwrap();
        let l = Location::open("secure", &f.locations["secure"], Some("hunter2")).unwrap();
        l.put("backups/a.bin", b"payload").unwrap();
        assert!(!std::fs::read(edir.join("backups/a.bin")).unwrap().windows(7).any(|w| w == b"payload"), "encrypted at rest");
        assert_eq!(l.get("backups/a.bin").unwrap().unwrap(), b"payload");
        assert!(l.put(MARKER_KEY, b"x").is_err());
        let wrong = |s: &str| s.replace("{{secret:SP}}", "wrong");
        assert!(run(&kit.paths, &args(&["list"]), &wrong).unwrap().contains("wrong-key"));
        assert!(r(&["init", "ghost"]).unwrap_err().contains("not configured"));
        assert!(r(&["add", "rel", "--path", "relative"]).is_err());
        r(&["rm", "plain"]).unwrap();
        assert!(dir.join(MARKER_KEY).exists(), "rm leaves files alone");
    }

    /// `seagent storage …` reaches this module through `ops::MODULES`; other names fall through.
    #[test]
    fn dispatch_is_wired() {
        let me: fn(&str, &Args, &[String]) -> Option<R> = dispatch;
        assert!(crate::ops::modules().iter().any(|m| m.0 == COMMANDS && m.3 as usize == me as usize), "storage::dispatch is registered in ops::MODULES");
        let a = args(&[]);
        assert!(dispatch("users", &a, &[]).is_none() && dispatch("project", &a, &[]).is_none());
    }
}
