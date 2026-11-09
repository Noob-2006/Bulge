//! The SE Agent app's device key (docs/SECURITY.md §8; host side
//! `crates/seagent-app/src/device_auth.rs`), kept in the platform's key store:
//!
//! | platform | first choice | then | last resort |
//! |---|---|---|---|
//! | Windows | CNG key in the **Microsoft Platform Crypto Provider** (TPM) | **Microsoft Software Key Storage Provider**, non-exportable | file |
//! | macOS / iOS | **Secure Enclave** key (Keychain item) | software **Keychain** key | file |
//! | Android | **Android Keystore** (StrongBox / TEE), via the app's mobile plugin ([`open`]'s `external`) | — | file |
//! | Linux | **TPM**: the key sealed with `systemd-creds --with-key=tpm2`, the same path the agent's vault uses (`seagent-kernel` secretstore) — root only, since for other users every unseal asks polkit | — | file |
//!
//! The choice is made once and written to `<dir>/device-key.json` (`{"store", "name"}`); later
//! starts open exactly that store and **never silently switch** (another store means another
//! key, which the host would refuse). A `device-key.p8` from an earlier version stays in use (the
//! host may already have bound it). `SEAGENT_DEVICE_KEY_STORE=<kind>` forces a store.
//! The private key never leaves the platform stores; the file fallback is a 0600 PKCS#8.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::path::Path;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
mod file;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
mod linux;
#[cfg(windows)]
mod win;

pub use file::FileStore;

/// Where the key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Windows: Platform Crypto Provider; Linux: systemd-creds TPM sealing.
    Tpm,
    /// Windows: Software Key Storage Provider (non-exportable).
    Cng,
    SecureEnclave,
    Keychain,
    AndroidKeystore,
    File,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Tpm => "tpm",
            Kind::Cng => "cng",
            Kind::SecureEnclave => "secure-enclave",
            Kind::Keychain => "keychain",
            Kind::AndroidKeystore => "android-keystore",
            Kind::File => "file",
        }
    }
    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s.trim() {
            "tpm" => Kind::Tpm,
            "cng" => Kind::Cng,
            "secure-enclave" => Kind::SecureEnclave,
            "keychain" => Kind::Keychain,
            "android-keystore" => Kind::AndroidKeystore,
            "file" => Kind::File,
            _ => return None,
        })
    }
}

/// A key store holding one P-256 signing key.
pub trait Store: Send + Sync {
    fn kind(&self) -> Kind;
    /// The 65-byte uncompressed public point.
    fn public_point(&self) -> Result<Vec<u8>, String>;
    /// ECDSA P-256 / SHA-256 over `msg`, as the 64-byte `r ‖ s` the host verifies.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String>;
}

/// Which platform the selection is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Macos,
    Ios,
    Android,
    Linux,
    Other,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "ios") {
            Os::Ios
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else if cfg!(target_os = "android") {
            Os::Android
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::Other
        }
    }
}

/// What this machine offers (probed once at selection time).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Probe {
    /// Windows: the Platform Crypto Provider opens (a TPM 2.0 is there).
    pub windows_tpm: bool,
    pub secure_enclave: bool,
    pub keychain: bool,
    /// Android: the app handed in a Keystore bridge.
    pub android_keystore: bool,
    /// Linux: `/dev/tpmrm0`, `systemd-creds has-tpm2` and root (no polkit prompt per unseal).
    pub linux_tpm: bool,
}

/// The stores to try, best first. The file is always last (and always works).
pub fn candidates(os: Os, p: &Probe) -> Vec<Kind> {
    let mut v = vec![];
    match os {
        Os::Windows => {
            if p.windows_tpm {
                v.push(Kind::Tpm);
            }
            v.push(Kind::Cng);
        }
        Os::Macos | Os::Ios => {
            if p.secure_enclave {
                v.push(Kind::SecureEnclave);
            }
            if p.keychain {
                v.push(Kind::Keychain);
            }
        }
        Os::Android => {
            if p.android_keystore {
                v.push(Kind::AndroidKeystore);
            }
        }
        Os::Linux => {
            if p.linux_tpm {
                v.push(Kind::Tpm);
            }
        }
        Os::Other => {}
    }
    v.push(Kind::File);
    v
}

/// A forced store (`SEAGENT_DEVICE_KEY_STORE`) narrows the list to that one store.
pub fn forced(list: Vec<Kind>, force: Option<&str>) -> Result<Vec<Kind>, String> {
    match force.map(str::trim).filter(|f| !f.is_empty()) {
        None => Ok(list),
        Some(f) => match Kind::parse(f) {
            Some(k) => Ok(vec![k]),
            None => Err(format!("SEAGENT_DEVICE_KEY_STORE={f}: use tpm, cng, secure-enclave, keychain, android-keystore or file")),
        },
    }
}

pub const RECORD: &str = "device-key.json";

/// `<dir>/device-key.json`: which store and which key name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub store: Kind,
    pub name: String,
}

impl Record {
    pub fn load(dir: &Path) -> Option<Record> {
        let s = std::fs::read_to_string(dir.join(RECORD)).ok()?;
        let store = Kind::parse(&json_field(&s, "store")?)?;
        Some(Record { store, name: json_field(&s, "name").unwrap_or_default() })
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        file::write_private(&dir.join(RECORD), format!("{{\"store\":\"{}\",\"name\":\"{}\"}}\n", self.store.as_str(), self.name).as_bytes())
    }
}

/// The value of `"key": "value"` in our own one-line JSON (no serde here).
fn json_field(s: &str, key: &str) -> Option<String> {
    let at = s.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = s[at..].trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

/// What signs with which store.
pub struct DeviceKey {
    store: Box<dyn Store>,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKey({})", self.store.kind().as_str())
    }
}

/// What the device signs (must match the host's `refresh_message`).
pub fn refresh_message(host_id: &str, device_id: &str, ts: u64, nonce: &str) -> String {
    format!("seagent-device-refresh|v1|{host_id}|{device_id}|{ts}|{nonce}")
}

impl DeviceKey {
    pub fn from_store(store: Box<dyn Store>) -> DeviceKey {
        DeviceKey { store }
    }
    pub fn kind(&self) -> Kind {
        self.store.kind()
    }
    /// base64url of the 65-byte public point (`device.publicKey`).
    pub fn public_b64(&self) -> Result<String, String> {
        let p = self.store.public_point()?;
        if p.len() != 65 || p[0] != 4 {
            return Err("the key store returned no P-256 public point".into());
        }
        Ok(URL_SAFE_NO_PAD.encode(p))
    }
    pub fn sign_b64(&self, msg: &[u8]) -> Result<String, String> {
        let s = self.store.sign(msg)?;
        if s.len() != 64 {
            return Err("the key store returned a malformed signature".into());
        }
        Ok(URL_SAFE_NO_PAD.encode(s))
    }
    /// The `POST /pair/refresh` body (`ts` from the host clock, `GET /pair/info`).
    pub fn refresh_body(&self, host_id: &str, device_id: &str, ts: u64) -> Result<String, String> {
        let mut n = [0u8; 18];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut n).map_err(|_| "no randomness".to_string())?;
        let nonce = URL_SAFE_NO_PAD.encode(n);
        let sig = self.sign_b64(refresh_message(host_id, device_id, ts, &nonce).as_bytes())?;
        Ok(format!("{{\"deviceId\":\"{device_id}\",\"ts\":{ts},\"nonce\":\"{nonce}\",\"sig\":\"{sig}\",\"publicKey\":\"{}\",\"keyStore\":\"{}\"}}", self.public_b64()?, self.kind().as_str()))
    }
}

fn new_name() -> String {
    let mut b = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    format!("seagent-device-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

/// What this machine offers right now.
pub fn probe(external: bool) -> Probe {
    Probe {
        #[cfg(windows)]
        windows_tpm: win::platform_provider_available(),
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        secure_enclave: true, // tried first; a Mac without one (or an unsigned build) falls through
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        keychain: true,
        android_keystore: external,
        #[cfg(all(target_os = "linux", not(target_os = "android")))]
        linux_tpm: linux::available(),
        ..Probe::default()
    }
}

/// Open (or create once) this install's device key in `dir`. `external`: a platform store the
/// app provides (Android Keystore through the mobile plugin).
pub fn open(dir: &Path, external: Option<Box<dyn Store>>) -> Result<DeviceKey, String> {
    if let Some(r) = Record::load(dir) {
        return open_kind(dir, r.store, &r.name, false, external).map(DeviceKey::from_store).map_err(|e| format!("the device key in {} ({}) cannot be opened: {e}; forget the host and pair it again", r.store.as_str(), dir.display()));
    }
    // A key from before the platform stores: keep it, the host may have bound it already.
    if dir.join(file::FILE).is_file() {
        Record { store: Kind::File, name: String::new() }.save(dir)?;
        return open_kind(dir, Kind::File, "", false, None).map(DeviceKey::from_store);
    }
    let list = forced(candidates(Os::current(), &probe(external.is_some())), std::env::var("SEAGENT_DEVICE_KEY_STORE").ok().as_deref())?;
    let mut external = external;
    let mut errors = vec![];
    for kind in list {
        let name = new_name();
        let ext = if kind == Kind::AndroidKeystore { external.take() } else { None };
        match open_kind(dir, kind, &name, true, ext) {
            Ok(store) => {
                // A store that cannot produce its public key is not usable after all.
                if let Err(e) = store.public_point() {
                    errors.push(format!("{}: {e}", kind.as_str()));
                    continue;
                }
                Record { store: kind, name }.save(dir)?;
                return Ok(DeviceKey::from_store(store));
            }
            Err(e) => errors.push(format!("{}: {e}", kind.as_str())),
        }
    }
    Err(format!("no key store worked: {}", errors.join("; ")))
}

fn open_kind(dir: &Path, kind: Kind, name: &str, create: bool, external: Option<Box<dyn Store>>) -> Result<Box<dyn Store>, String> {
    let _ = (name, create);
    match kind {
        Kind::File => Ok(Box::new(FileStore::open(dir)?)),
        Kind::AndroidKeystore => external.ok_or_else(|| "no Android Keystore bridge here".to_string()),
        #[cfg(windows)]
        Kind::Tpm => Ok(Box::new(win::Cng::open(name, true, create)?)),
        #[cfg(windows)]
        Kind::Cng => Ok(Box::new(win::Cng::open(name, false, create)?)),
        #[cfg(all(target_os = "linux", not(target_os = "android")))]
        Kind::Tpm => Ok(Box::new(linux::Sealed::open(dir, create, &linux::tool())?)),
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        Kind::SecureEnclave => Ok(Box::new(apple::Keychain::open(name, true, create)?)),
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        Kind::Keychain => Ok(Box::new(apple::Keychain::open(name, false, create)?)),
        #[allow(unreachable_patterns)]
        k => Err(format!("{} is not available on this platform", k.as_str())),
    }
}

/// Delete the key a record names (tests; "forget this device" could use it too).
pub fn destroy(dir: &Path) -> Result<(), String> {
    let r = Record::load(dir);
    #[cfg(windows)]
    if let Some(r) = &r {
        if matches!(r.store, Kind::Tpm | Kind::Cng) {
            win::Cng::delete(&r.name, r.store == Kind::Tpm)?;
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some(r) = &r {
        if matches!(r.store, Kind::SecureEnclave | Kind::Keychain) {
            apple::Keychain::delete(&r.name)?;
        }
    }
    let _ = r;
    for f in [RECORD, file::FILE, "device-key.tpm"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    Ok(())
}

/// X9.62 DER `SEQUENCE { INTEGER r, INTEGER s }` → 64-byte `r ‖ s` (Keychain and Android
/// Keystore sign in DER; the host and WebCrypto use the fixed form).
pub fn der_to_p1363(der: &[u8]) -> Result<Vec<u8>, String> {
    let bad = || "malformed DER ECDSA signature".to_string();
    let mut i = 0;
    let mut take = |n: usize| -> Result<&[u8], String> {
        let s = der.get(i..i + n).ok_or_else(bad)?;
        i += n;
        Ok(s)
    };
    if take(1)? != [0x30] {
        return Err(bad());
    }
    let len = take(1)?[0] as usize;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        take(n)?;
    }
    let mut out = Vec::with_capacity(64);
    for _ in 0..2 {
        if take(1)? != [0x02] {
            return Err(bad());
        }
        let n = take(1)?[0] as usize;
        let v = take(n)?;
        let v = &v[v.iter().take_while(|b| **b == 0).count().min(v.len().saturating_sub(1))..];
        if v.len() > 32 {
            return Err(bad());
        }
        out.extend(vec![0u8; 32 - v.len()]);
        out.extend_from_slice(v);
    }
    Ok(out)
}

/// The 65-byte point inside a P-256 X.509 SubjectPublicKeyInfo (Android's `getEncoded()`).
pub fn spki_to_point(spki: &[u8]) -> Result<Vec<u8>, String> {
    // 0x30 0x59 … BIT STRING 0x03 0x42 0x00 then the point: the last 65 bytes.
    if spki.len() == 91 && spki[0] == 0x30 && spki[spki.len() - 65] == 4 && spki[23..26] == [0x03, 0x42, 0x00] {
        return Ok(spki[26..].to_vec());
    }
    Err("not a P-256 public key".into())
}

/// For `seagent doctor` / the app's info page: the record, without touching the store.
pub fn describe(dir: &Path) -> Option<String> {
    Record::load(dir).map(|r| r.store.as_str().to_string()).or_else(|| dir.join(file::FILE).is_file().then(|| "file".to_string()))
}

#[cfg(test)]
mod tests;
