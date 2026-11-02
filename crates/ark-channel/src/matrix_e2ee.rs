//! Matrix end-to-end encryption (client-server spec §"End-to-End Encryption"):
//! the device crypto state behind [`crate::matrix::Matrix`], built on [`crate::olm`].
//!
//! - Device keys (Ed25519 + Curve25519) are signed and uploaded once; signed
//!   one-time keys are kept at 50 on the server (`device_one_time_keys_count`)
//!   and a signed fallback key is rotated once the server reports it used.
//! - To-device `m.room.encrypted` (Olm) is decrypted (pre-key messages open new
//!   inbound sessions); the plaintext's `sender`/`recipient`/`recipient_keys`/
//!   `keys` are checked, and `m.room_key` is accepted only from a device of the
//!   sending user whose Curve25519/Ed25519 keys match what `keys/query` reports.
//! - Room events (Megolm) decrypt only with a session from the event's sender;
//!   each (session, index) is bound to one event id (replay protection).
//! - Sending: one outbound Megolm session per room, rotated by the room's
//!   `rotation_period_ms`/`rotation_period_msgs` (defaults 1 week / 100) or when
//!   a recipient device goes away; keys are shared over Olm (`keys/claim` for new
//!   sessions) with every non-blocked device of every joined member.
//! - Trust: TOFU. A device whose identity keys change is blocked; configured
//!   blacklist entries (`DEVICE`, `@user:hs`, `@user:hs/DEVICE`) never receive
//!   keys and are not trusted for decryption. Cross-signing identities (master
//!   → self-signing → device signatures) are checked on every `keys/query` and
//!   the master key is pinned; with `trust = "cross_signed"` devices of users
//!   with cross-signing keys must be cross-signed (or SAS-verified) and a changed
//!   master key blocks them until re-verified. Cross-signing bootstrap, SAS,
//!   secret storage and key backup live in [`crate::matrix_trust`].
//! - Key requests: missing Megolm sessions are requested (`m.room_key_request`)
//!   from our own devices and the sender's device; `m.forwarded_room_key` is
//!   accepted only for sessions we asked for, from our own verified devices or
//!   the session's own device. Requests from our own verified devices are
//!   answered. An Olm message no session can decrypt makes us open a fresh
//!   session and send `m.dummy` (at most once an hour per device).
//! - Invited members get room keys too unless `history_visibility` is `joined`.
//! - Store: JSON encrypted with AES-256-GCM, 0600 (key from PBKDF2 over a
//!   passphrase, or a random key file next to it).
//! - Attachments: `EncryptedFile` v2 (AES-256-CTR, SHA-256 of the ciphertext).

use crate::olm::{self, b64, key32, unb64, Account, GroupInbound, GroupOutbound, OlmError, Session};
use crate::{write_private, ChannelError, ChannelErrorKind as K};
use ark_net::crypto::{random_bytes, sha256, Aes};
use ark_net::urlencode as enc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const OLM: &str = "m.olm.v1.curve25519-aes-sha2";
pub const MEGOLM: &str = "m.megolm.v1.aes-sha2";
const OTK_TARGET: u64 = 50;
const PBKDF2_ROUNDS: u32 = 100_000;
const MAX_SESSIONS_PER_DEVICE: usize = 20;
const MAX_SEEN_PER_SESSION: usize = 5000;
const MAX_FILES: usize = 500;
const NO_KEY_RETRY: Duration = Duration::from_secs(600);
const UNWEDGE_EVERY_MS: u64 = 3_600_000;
const KEY_REQUEST_TTL_MS: u64 = 86_400_000;

/// `(method, path, body)` → JSON; `Value::Null` body = no body.
pub type Call<'a> = &'a dyn Fn(&str, &str, Value) -> Result<Value, ChannelError>;

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub(crate) fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

pub(crate) fn fatal(m: impl Into<String>) -> ChannelError {
    ChannelError::new(K::Fatal, m)
}

/// Canonical JSON of `v` without `signatures`/`unsigned` (the signed bytes).
pub(crate) fn signable(v: &Value) -> String {
    let mut c = v.clone();
    if let Some(o) = c.as_object_mut() {
        o.remove("signatures");
        o.remove("unsigned");
    }
    crate::reef::canonical(&c)
}

pub fn verify_json(v: &Value, user: &str, key_id: &str, ed25519: &str) -> bool {
    let (Some(sig), Some(pk)) = (v["signatures"][user][key_id].as_str().and_then(unb64), unb64(ed25519)) else { return false };
    ark_net::crypto::ed25519_verify(&pk, signable(v).as_bytes(), &sig)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Device {
    pub ed25519: String,
    pub curve25519: String,
    /// Why it is blocked (TOFU violation), if it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// Verified by us (SAS).
    #[serde(default)]
    pub verified: bool,
    /// Signed by its owner's self-signing key (which the owner's master key signed).
    #[serde(default)]
    pub cross_signed: bool,
    /// The signed `device_keys` object (for re-signing our own devices).
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub keys: Value,
}

/// A user's cross-signing identity as last seen (the master key is pinned).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Identity {
    pub master: String,
    #[serde(default)]
    pub self_signing: Option<String>,
    #[serde(default)]
    pub user_signing: Option<String>,
    /// Master key verified (SAS, our user-signing signature, or our own private key).
    #[serde(default)]
    pub verified: bool,
    /// The master key changed since we pinned it and has not been re-verified.
    #[serde(default)]
    pub changed: bool,
    /// The master key object as published (for signing it with our user-signing key).
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub master_obj: Value,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct InboundRec {
    pub session: GroupInbound,
    /// Sending user (empty: not yet attributed).
    pub sender: String,
    pub sender_key: String,
    #[serde(default)]
    pub seen: BTreeMap<u32, String>,
    /// The sender device's Ed25519 key as claimed when we got the session.
    #[serde(default)]
    pub claimed_ed25519: String,
    /// Curve25519 keys of devices that forwarded it to us (empty: direct `m.room_key`).
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub backed_up: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct OutboundRec {
    pub session: GroupOutbound,
    pub created_ms: u64,
    pub messages: u64,
    /// `"user device"` keys this session was shared with.
    pub shared: BTreeSet<String>,
}

/// Our cross-signing private keys (Ed25519 seeds).
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CrossKeys {
    pub master: Option<[u8; 32]>,
    pub self_signing: Option<[u8; 32]>,
    pub user_signing: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct BackupKey {
    pub version: String,
    pub secret: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KeyRequest {
    pub id: String,
    pub sender: String,
    pub ms: u64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Store {
    pub user_id: String,
    pub device_id: String,
    pub account: Account,
    pub uploaded: bool,
    /// Olm sessions by peer Curve25519 key.
    pub sessions: HashMap<String, Vec<Session>>,
    /// `"room\nsession_id"` → inbound Megolm session.
    pub inbound: HashMap<String, InboundRec>,
    pub outbound: HashMap<String, OutboundRec>,
    pub devices: HashMap<String, BTreeMap<String, Device>>,
    pub outdated: BTreeSet<String>,
    /// mxc url → `EncryptedFile` (for `fetch_media`), oldest first.
    pub files: Vec<(String, Value)>,
    #[serde(default)]
    pub identities: HashMap<String, Identity>,
    #[serde(default)]
    pub cross: Option<CrossKeys>,
    /// Secret-storage key we created or were given (`(key id, key)`).
    #[serde(default)]
    pub ssss: Option<(String, [u8; 32])>,
    #[serde(default)]
    pub backup: Option<BackupKey>,
    /// Peer Curve25519 key → when we last sent it an unwedging `m.dummy`.
    #[serde(default)]
    pub dummy_sent: HashMap<String, u64>,
    /// `"room\nsession_id"` → our outstanding `m.room_key_request`.
    #[serde(default)]
    pub requested: BTreeMap<String, KeyRequest>,
    #[serde(default)]
    pub startup_verify_ms: u64,
}

#[derive(Default)]
pub(crate) struct Mem {
    pub members: HashMap<String, Vec<String>>,
    /// Room → `history_visibility`.
    pub visibility: HashMap<String, String>,
    pub no_key: HashMap<String, Instant>,
    pub dirty: bool,
    pub flows: HashMap<String, crate::matrix_sas::Flow>,
    /// Flow id → devices a to-device request went to.
    pub flow_targets: HashMap<String, Vec<String>>,
    /// Secret request id → (secret name, device it was asked from).
    pub secret_requests: HashMap<String, (String, String)>,
    pub out: Vec<Out>,
}

/// Work for the transport layer (`matrix`): room events and notices for humans.
#[derive(Debug, Clone, PartialEq)]
pub enum Out {
    /// Send `content` as `typ` in `room`; for `m.room.message` verification requests
    /// `flow_for` names the user, and the resulting event id becomes the flow id.
    Room { room: String, typ: String, content: Value, flow_for: Option<String> },
    Notice(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    #[default]
    Tofu,
    CrossSigned,
}

/// Trust, cross-signing, backup and verification policy (from the channel config).
#[derive(Clone, Debug)]
pub struct Opts {
    pub trust: Trust,
    pub cross_signing: bool,
    pub key_backup: bool,
    pub recovery_key: Option<String>,
    /// Users whose verification requests are answered (`self` = our own user, `*` = anyone).
    pub verify_from: Vec<String>,
    /// Ask our other devices to verify this one at startup if it is not cross-signed.
    pub startup_verification: bool,
    pub startup_verification_cooldown_ms: u64,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts { trust: Trust::Tofu, cross_signing: true, key_backup: true, recovery_key: None, verify_from: vec!["self".into()], startup_verification: true, startup_verification_cooldown_ms: 86_400_000 }
    }
}

#[derive(Debug, PartialEq)]
pub enum DecryptError {
    /// No session (yet): the key may still arrive.
    MissingSession,
    Rejected(String),
}

pub struct E2ee {
    pub(crate) label: String,
    pub(crate) path: PathBuf,
    key: [u8; 32],
    header: Value,
    pub(crate) st: Mutex<Store>,
    pub(crate) mem: Mutex<Mem>,
    pub blacklist: Vec<String>,
    pub opts: Opts,
}

fn gcm(key: &[u8; 32]) -> ring::aead::LessSafeKey {
    ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key).expect("aes key"))
}

const AAD: &[u8] = b"ark-matrix-e2ee-v1";

fn pbkdf2(pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, std::num::NonZeroU32::new(PBKDF2_ROUNDS).unwrap(), salt, pass.as_bytes(), &mut k);
    k
}

impl E2ee {
    /// Open (or create) the store for `user`/`device`. A store of another device is replaced.
    pub fn open(label: &str, path: &Path, passphrase: Option<&str>, user: &str, device: &str) -> Result<E2ee, String> {
        let keyfile = path.with_extension("e2ee.key");
        let existing = match std::fs::read_to_string(path) {
            Ok(t) => Some(serde_json::from_str::<Value>(&t).map_err(|e| format!("matrix e2ee store {}: {e}", path.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        let key_for = |h: &Value| -> Result<[u8; 32], String> {
            match (s(&h["kdf"]), passphrase) {
                ("pbkdf2", Some(p)) => Ok(pbkdf2(p, &unb64(s(&h["salt"])).ok_or("bad salt")?)),
                ("pbkdf2", None) => Err("matrix e2ee store is passphrase-protected but no e2ee_passphrase is configured".into()),
                _ => std::fs::read(&keyfile).ok().and_then(|k| k.try_into().ok()).ok_or_else(|| format!("matrix e2ee key file {} missing or invalid", keyfile.display())),
            }
        };
        if let Some(env) = existing {
            let key = key_for(&env)?;
            let mut ct = unb64(s(&env["ct"])).ok_or("bad store ciphertext")?;
            let nonce: [u8; 12] = unb64(s(&env["nonce"])).and_then(|n| n.try_into().ok()).ok_or("bad store nonce")?;
            let plain = gcm(&key).open_in_place(ring::aead::Nonce::assume_unique_for_key(nonce), ring::aead::Aad::from(AAD), &mut ct).map_err(|_| "matrix e2ee store: wrong passphrase/key or corrupted file".to_string())?;
            let st: Store = serde_json::from_slice(plain).map_err(|e| format!("matrix e2ee store: {e}"))?;
            if st.user_id == user && st.device_id == device {
                let header = json!({"v": 1, "kdf": env["kdf"], "salt": env["salt"]});
                return Ok(E2ee { label: label.into(), path: path.into(), key, header, st: Mutex::new(st), mem: Mutex::default(), blacklist: vec![], opts: Opts::default() });
            }
            eprintln!("matrix {label}: e2ee store belongs to {} / {}; starting a new one for {user} / {device}", st.user_id, st.device_id);
        }
        let (key, header) = match passphrase {
            Some(p) => {
                let salt = random_bytes(16);
                (pbkdf2(p, &salt), json!({"v": 1, "kdf": "pbkdf2", "salt": b64(&salt)}))
            }
            None => {
                let k: [u8; 32] = random_bytes(32).try_into().unwrap();
                write_private(&keyfile, &k).map_err(|e| format!("writing {}: {e}", keyfile.display()))?;
                (k, json!({"v": 1, "kdf": "keyfile"}))
            }
        };
        let st = Store {
            user_id: user.into(),
            device_id: device.into(),
            account: Account::generate(),
            uploaded: false,
            sessions: HashMap::new(),
            inbound: HashMap::new(),
            outbound: HashMap::new(),
            devices: HashMap::new(),
            outdated: BTreeSet::new(),
            files: vec![],
            identities: HashMap::new(),
            cross: None,
            ssss: None,
            backup: None,
            dummy_sent: HashMap::new(),
            requested: BTreeMap::new(),
            startup_verify_ms: 0,
        };
        let e = E2ee { label: label.into(), path: path.into(), key, header, st: Mutex::new(st), mem: Mutex::default(), blacklist: vec![], opts: Opts::default() };
        e.save(&e.st.lock().unwrap()).map_err(|e| e.message)?;
        Ok(e)
    }

    pub(crate) fn save(&self, st: &Store) -> Result<(), ChannelError> {
        let mut data = serde_json::to_vec(st).map_err(|e| fatal(format!("e2ee store: {e}")))?;
        let nonce: [u8; 12] = random_bytes(12).try_into().unwrap();
        gcm(&self.key).seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce), ring::aead::Aad::from(AAD), &mut data).map_err(|_| fatal("e2ee seal"))?;
        let mut env = self.header.clone();
        env["nonce"] = json!(b64(&nonce));
        env["ct"] = json!(b64(&data));
        self.mem.lock().unwrap().dirty = false;
        write_private(&self.path, env.to_string().as_bytes()).map_err(|e| fatal(format!("saving matrix e2ee store: {e}")))
    }

    /// Persist changes made by decryption (replay bookkeeping).
    pub fn flush(&self) {
        if self.mem.lock().unwrap().dirty {
            let st = self.st.lock().unwrap();
            if let Err(e) = self.save(&st) {
                eprintln!("matrix {}: {e}", self.label);
            }
        }
    }

    pub fn identity(&self) -> (String, String) {
        let st = self.st.lock().unwrap();
        (st.account.ed25519(), st.account.curve25519())
    }

    pub(crate) fn sign(st: &Store, v: &mut Value) {
        let sig = st.account.sign(signable(v).as_bytes());
        v["signatures"] = json!({ st.user_id.clone(): { format!("ed25519:{}", st.device_id): sig } });
    }

    pub(crate) fn device_keys(st: &Store) -> Value {
        let mut v = json!({"user_id": st.user_id, "device_id": st.device_id, "algorithms": [OLM, MEGOLM], "keys": {
            format!("curve25519:{}", st.device_id): st.account.curve25519(), format!("ed25519:{}", st.device_id): st.account.ed25519()}});
        Self::sign(st, &mut v);
        v
    }

    /// Upload device keys (once) and any unpublished one-time / fallback keys.
    fn upload(&self, st: &mut Store, call: Call) -> Result<(), ChannelError> {
        let mut body = json!({});
        if !st.uploaded {
            body["device_keys"] = Self::device_keys(st);
        }
        let mut otks = serde_json::Map::new();
        for k in st.account.one_time.iter().filter(|k| !k.published) {
            let mut v = json!({"key": b64(&k.key.public)});
            Self::sign(st, &mut v);
            otks.insert(format!("signed_curve25519:{}", olm::key_id(k.id)), v);
        }
        if !otks.is_empty() {
            body["one_time_keys"] = Value::Object(otks);
        }
        if let Some(f) = st.account.fallback.as_ref().filter(|f| !f.published) {
            let mut v = json!({"key": b64(&f.key.public), "fallback": true});
            Self::sign(st, &mut v);
            body["fallback_keys"] = json!({ format!("signed_curve25519:{}", olm::key_id(f.id)): v });
        }
        if body.as_object().is_some_and(|o| o.is_empty()) {
            return Ok(());
        }
        call("POST", "/_matrix/client/v3/keys/upload", body)?;
        st.uploaded = true;
        st.account.one_time.iter_mut().for_each(|k| k.published = true);
        if let Some(f) = st.account.fallback.as_mut() {
            f.published = true;
        }
        self.save(st)
    }

    /// First run: device keys, 50 one-time keys and a fallback key.
    pub fn ensure_uploaded(&self, call: Call) -> Result<(), ChannelError> {
        let mut st = self.st.lock().unwrap();
        if !st.uploaded {
            if st.account.one_time.is_empty() {
                st.account.generate_one_time_keys(OTK_TARGET as usize);
            }
            if st.account.fallback.is_none() {
                st.account.generate_fallback_key();
            }
        }
        self.upload(&mut st, call)
    }

    /// Why `user`'s device `dev` must neither get keys nor be believed, if so.
    pub(crate) fn distrust(&self, st: &Store, user: &str, dev: &str, d: &Device) -> Option<String> {
        if let Some(b) = &d.blocked {
            return Some(b.clone());
        }
        if self.blacklist.iter().any(|b| b == dev || b == user || *b == format!("{user}/{dev}")) {
            return Some("blacklisted".into());
        }
        if self.opts.trust == Trust::CrossSigned && !d.verified {
            if let Some(id) = st.identities.get(user) {
                if id.changed {
                    return Some("cross-signing identity changed and is not re-verified".into());
                }
                if !d.cross_signed {
                    return Some("not cross-signed by its owner".into());
                }
            }
        }
        None
    }

    /// One of our own other devices that we verified, or that our (trusted) identity cross-signed.
    pub(crate) fn own_verified(st: &Store, dev: &str) -> Option<Device> {
        let d = st.devices.get(&st.user_id)?.get(dev)?;
        let id_ok = st.identities.get(&st.user_id).is_some_and(|i| i.verified && !i.changed);
        (dev != st.device_id && d.blocked.is_none() && (d.verified || (d.cross_signed && id_ok))).then(|| d.clone())
    }

    /// The device of `user` with Curve25519 key `curve` (querying keys once if unknown).
    pub(crate) fn device_by_curve(&self, st: &mut Store, user: &str, curve: &str, call: Call) -> Option<(String, Device)> {
        let find = |st: &Store| st.devices.get(user).and_then(|m| m.iter().find(|(_, d)| d.curve25519 == curve).map(|(k, d)| (k.clone(), d.clone())));
        if find(st).is_none() {
            st.outdated.insert(user.to_string());
            if let Err(e) = self.ensure_devices(st, &[user.to_string()], call) {
                eprintln!("matrix {}: keys/query {user}: {e}", self.label);
            }
        }
        find(st)
    }

    /// The Ed25519 key of a cross-signing key object (`usage` and `user_id` checked).
    fn cross_key(v: &Value, user: &str, usage: &str) -> Option<String> {
        let keys = v["keys"].as_object().filter(|k| k.len() == 1)?;
        let (id, k) = keys.iter().next()?;
        (v["user_id"] == user && v["usage"].as_array().is_some_and(|a| a.iter().any(|x| x == usage)) && id.strip_prefix("ed25519:") == k.as_str()).then(|| s(k).to_string())
    }

    /// `keys/query` for users we know nothing about or whose devices changed. TOFU: a
    /// device id that comes back with different identity keys is blocked. Cross-signing
    /// keys are checked (self-signing signed by master, devices by self-signing) and the
    /// master key pinned.
    pub(crate) fn ensure_devices(&self, st: &mut Store, users: &[String], call: Call) -> Result<(), ChannelError> {
        let need: Vec<&String> = users.iter().filter(|u| !st.devices.contains_key(*u) || st.outdated.contains(*u)).collect();
        if need.is_empty() {
            return Ok(());
        }
        let q: serde_json::Map<String, Value> = need.iter().map(|u| (u.to_string(), json!([]))).collect();
        let r = call("POST", "/_matrix/client/v3/keys/query", json!({"device_keys": q, "timeout": 10000}))?;
        let me = st.user_id.clone();
        let our_usk = st.identities.get(&me).and_then(|i| i.user_signing.clone());
        let our_master = st.cross.as_ref().and_then(|c| c.master).map(|m| b64(&olm::ed25519_public(&m)));
        for u in need {
            let Some(got) = r["device_keys"][u.as_str()].as_object() else { continue };
            let old = st.devices.remove(u.as_str()).unwrap_or_default();
            let mut id = None;
            if let Some(master) = Self::cross_key(&r["master_keys"][u.as_str()], u, "master") {
                let signed_by = |v: &Value, usage: &str| Self::cross_key(v, u, usage).filter(|_| verify_json(v, u, &format!("ed25519:{master}"), &master));
                let ssk = signed_by(&r["self_signing_keys"][u.as_str()], "self_signing");
                let usk = signed_by(&r["user_signing_keys"][u.as_str()], "user_signing");
                let prev = st.identities.get(u.as_str()).cloned();
                let mobj = r["master_keys"][u.as_str()].clone();
                let by_us = *u == me && our_master.as_deref() == Some(master.as_str());
                let by_usk = *u != me && our_usk.as_ref().is_some_and(|k| verify_json(&mobj, &me, &format!("ed25519:{k}"), k));
                let mut i = Identity { master: master.clone(), self_signing: ssk, user_signing: usk, verified: by_us || by_usk, changed: false, master_obj: mobj };
                match prev {
                    Some(p) if p.master == master => {
                        i.verified |= p.verified;
                        i.changed = p.changed && !i.verified;
                    }
                    Some(p) => {
                        eprintln!("matrix {}: {u} has a new cross-signing master key ({} → {master})", self.label, p.master);
                        i.changed = !i.verified && self.opts.trust == Trust::CrossSigned;
                    }
                    None => {}
                }
                id = Some(i);
            }
            let mut new = BTreeMap::new();
            for (dev, k) in got {
                let (ed, cu) = (s(&k["keys"][format!("ed25519:{dev}")]), s(&k["keys"][format!("curve25519:{dev}")]));
                if k["user_id"] != u.as_str() || k["device_id"] != dev.as_str() || ed.is_empty() || cu.is_empty() || !verify_json(k, u, &format!("ed25519:{dev}"), ed) {
                    eprintln!("matrix {}: ignoring device {u} {dev}: bad or unsigned device keys", self.label);
                    continue;
                }
                let cross_signed = id.as_ref().and_then(|i: &Identity| i.self_signing.as_ref()).is_some_and(|ssk| verify_json(k, u, &format!("ed25519:{ssk}"), ssk));
                let mut d = Device { ed25519: ed.into(), curve25519: cu.into(), blocked: None, verified: false, cross_signed, keys: k.clone() };
                if let Some(o) = old.get(dev) {
                    if o.ed25519 != d.ed25519 || o.curve25519 != d.curve25519 {
                        eprintln!("matrix {}: device {u} {dev} changed its identity keys; blocking it", self.label);
                        d.blocked = Some("identity keys changed".into());
                    } else {
                        d.blocked = o.blocked.clone();
                        d.verified = o.verified;
                    }
                }
                new.insert(dev.clone(), d);
            }
            st.devices.insert(u.clone(), new);
            match id {
                Some(i) => {
                    st.identities.insert(u.clone(), i);
                }
                // Cross-signing keys gone: under `cross_signed` trust keep the pin, flagged
                // (no silent downgrade to TOFU).
                None if self.opts.trust == Trust::CrossSigned && st.identities.contains_key(u.as_str()) => {
                    eprintln!("matrix {}: {u} no longer publishes cross-signing keys", self.label);
                    st.identities.get_mut(u.as_str()).unwrap().changed = true;
                }
                None => {
                    st.identities.remove(u.as_str());
                }
            }
            st.outdated.remove(u.as_str());
        }
        Ok(())
    }

    /// Our view of `user`'s devices (for tests / diagnostics).
    pub fn devices(&self, user: &str) -> BTreeMap<String, Device> {
        self.st.lock().unwrap().devices.get(user).cloned().unwrap_or_default()
    }

    /// Process the E2EE parts of a `/sync` response: device list changes, membership
    /// (outbound session rotation), to-device events, one-time / fallback key counts.
    pub fn on_sync(&self, sync: &Value, call: Call) {
        let mut st = self.st.lock().unwrap();
        let mut touched = false;
        for u in sync["device_lists"]["changed"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            if st.devices.contains_key(u) {
                touched |= st.outdated.insert(u.to_string());
            }
        }
        for u in sync["device_lists"]["left"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            touched |= st.devices.remove(u).is_some();
            st.outdated.remove(u);
        }
        let mut mem = self.mem.lock().unwrap();
        for (room, r) in sync["rooms"]["join"].as_object().into_iter().flatten() {
            for e in r["state"]["events"].as_array().into_iter().flatten().chain(r["timeline"]["events"].as_array().into_iter().flatten()) {
                if e["type"] == "m.room.member" {
                    mem.members.remove(room);
                    if !matches!(s(&e["content"]["membership"]), "join" | "invite") && st.outbound.remove(room).is_some() {
                        mem.dirty = true;
                    }
                } else if e["type"] == "m.room.history_visibility" {
                    mem.members.remove(room);
                    mem.visibility.insert(room.clone(), s(&e["content"]["history_visibility"]).to_string());
                }
            }
        }
        for room in sync["rooms"]["leave"].as_object().into_iter().flatten().map(|(k, _)| k) {
            mem.members.remove(room);
            touched |= st.outbound.remove(room).is_some();
        }
        drop(mem);
        for ev in sync["to_device"]["events"].as_array().into_iter().flatten() {
            let (sender, c) = (s(&ev["sender"]), &ev["content"]);
            let r = match s(&ev["type"]) {
                "m.room.encrypted" => self.to_device(&mut st, ev, call),
                "m.room_key_request" => self.on_key_request(&mut st, sender, c, call),
                "m.secret.request" => self.on_secret_request(&mut st, sender, c, call),
                t if t.starts_with("m.key.verification.") => self.on_verification(&mut st, sender, t, c, None, call),
                _ => Ok(()),
            };
            if let Err(e) = r {
                eprintln!("matrix {}: to-device {} from {sender}: {e}", self.label, s(&ev["type"]));
            }
        }
        let mut upload = false;
        if let Some(n) = sync["device_one_time_keys_count"].as_object().map(|o| o.get("signed_curve25519").and_then(Value::as_u64).unwrap_or(0)) {
            let unpublished = st.account.one_time.iter().filter(|k| !k.published).count() as u64;
            if n + unpublished < OTK_TARGET {
                st.account.generate_one_time_keys((OTK_TARGET - n - unpublished) as usize);
                upload = true;
            }
        }
        if let Some(types) = sync["device_unused_fallback_key_types"].as_array() {
            if !types.iter().any(|t| t == "signed_curve25519") && st.uploaded {
                st.account.generate_fallback_key();
                upload = true;
            }
        }
        let r = if upload || st.account.one_time.iter().any(|k| !k.published) {
            self.upload(&mut st, call)
        } else if touched || self.mem.lock().unwrap().dirty {
            self.save(&st)
        } else {
            Ok(())
        };
        if let Err(e) = r {
            eprintln!("matrix {}: e2ee key upload: {e}", self.label);
        }
        self.backup_pending(&mut st, call);
        self.expire_flows();
    }

    fn olm_decrypt(st: &mut Store, sender_key: &str, typ: u64, body: &[u8]) -> Result<Vec<u8>, String> {
        let now = now_ms();
        let sessions = st.sessions.entry(sender_key.to_string()).or_default();
        if typ == 0 {
            let p = olm::PreKey::parse(body).map_err(|e| e.to_string())?;
            if let Some(s) = sessions.iter_mut().find(|s| s.matches(body)) {
                s.last_used = now;
                return s.decrypt(&p.message).map_err(|e| e.to_string());
            }
            if key32(sender_key) != Some(p.identity) {
                return Err("pre-key identity key does not match sender_key".into());
            }
            let (mut s, plain) = st.account.inbound_session(body).map_err(|e| e.to_string())?;
            s.last_used = now;
            sessions.push(s);
            let extra = sessions.len().saturating_sub(MAX_SESSIONS_PER_DEVICE);
            sessions.drain(..extra);
            return Ok(plain);
        }
        sessions.sort_by_key(|s| std::cmp::Reverse(s.last_used));
        for s in sessions.iter_mut() {
            if let Ok(p) = s.decrypt(body) {
                s.last_used = now;
                return Ok(p);
            }
        }
        Err(if sessions.is_empty() { "no Olm session with this device".into() } else { "no Olm session could decrypt it".into() })
    }

    fn to_device(&self, st: &mut Store, ev: &Value, call: Call) -> Result<(), String> {
        let c = &ev["content"];
        if c["algorithm"] != OLM {
            return Err(format!("unsupported algorithm {}", c["algorithm"]));
        }
        let (sender, sender_key) = (s(&ev["sender"]), s(&c["sender_key"]));
        let mine = &c["ciphertext"][st.account.curve25519()];
        let body = unb64(s(&mine["body"])).ok_or("no ciphertext for this device")?;
        let plain = match Self::olm_decrypt(st, sender_key, mine["type"].as_u64().unwrap_or(1), &body) {
            Ok(p) => p,
            Err(e) => {
                self.unwedge(st, sender, sender_key, call);
                return Err(e);
            }
        };
        self.mem.lock().unwrap().dirty = true;
        let p: Value = serde_json::from_slice(&plain).map_err(|_| "plaintext is not JSON")?;
        if p["sender"] != sender || p["recipient"] != st.user_id.as_str() || p["recipient_keys"]["ed25519"] != st.account.ed25519() {
            return Err("sender/recipient mismatch in Olm payload".into());
        }
        if p["type"] == "m.dummy" {
            return Ok(());
        }
        // Bind the Olm sender key to a device of `sender` (TOFU / blacklist).
        let (dev, d) = self.device_by_curve(st, sender, sender_key, call).ok_or("sender_key is not a known device of the sender")?;
        if p["keys"]["ed25519"] != d.ed25519.as_str() {
            return Err("Ed25519 key in payload does not match the device".into());
        }
        let typ = s(&p["type"]);
        if typ.starts_with("m.key.verification.") {
            // Verification is how distrusted devices become trusted: no trust check here.
            return self.on_verification(st, sender, typ, &p["content"], None, call);
        }
        if let Some(why) = self.distrust(st, sender, &dev, &d) {
            return Err(format!("device {dev}: {why}"));
        }
        match typ {
            "m.room_key" => {}
            "m.forwarded_room_key" => return self.on_forwarded_key(st, sender, &d, &p["content"], call),
            "m.secret.send" => return self.on_secret_send(st, sender, &dev, &p["content"], call),
            _ => return Ok(()),
        }
        let k = &p["content"];
        if k["algorithm"] != MEGOLM {
            return Err(format!("unsupported room key algorithm {}", k["algorithm"]));
        }
        let g = GroupInbound::from_session_key(s(&k["session_key"])).map_err(|e| e.to_string())?;
        if g.id() != s(&k["session_id"]) {
            return Err("session_id does not match session_key".into());
        }
        let rec = InboundRec { session: g, sender: sender.into(), sender_key: sender_key.into(), seen: BTreeMap::new(), claimed_ed25519: d.ed25519.clone(), chain: vec![], backed_up: false };
        self.add_inbound(st, s(&k["room_id"]), rec, call);
        Ok(())
    }

    /// Keep a received session unless we already have it from an earlier index;
    /// it answers any outstanding key request of ours.
    pub(crate) fn add_inbound(&self, st: &mut Store, room: &str, rec: InboundRec, call: Call) -> bool {
        let id = format!("{room}\n{}", rec.session.id());
        if st.inbound.get(&id).is_some_and(|o| o.session.first_index() <= rec.session.first_index() && !o.sender.is_empty()) {
            return false;
        }
        st.inbound.insert(id.clone(), rec);
        self.mem.lock().unwrap().dirty = true;
        if let Some(req) = st.requested.remove(&id) {
            let me = st.user_id.clone();
            let c = json!({"action": "request_cancellation", "request_id": req.id, "requesting_device_id": st.device_id});
            let _ = call("PUT", &format!("/_matrix/client/v3/sendToDevice/m.room_key_request/{}", enc(&format!("ark-krc-{}", ark_net::crypto::random_token(9)))), json!({"messages": { me: {"*": c} }}));
        }
        true
    }

    /// Send one Olm-encrypted to-device event to each target (opening sessions as needed).
    pub(crate) fn send_olm(&self, st: &mut Store, to: &[(String, String, Device)], typ: &str, content: &Value, call: Call) -> Result<usize, String> {
        self.claim(st, to, false, call).map_err(|e| e.to_string())?;
        let mut msgs = serde_json::Map::new();
        let mut n = 0;
        for (u, d, dev) in to {
            if let Some(c) = Self::olm_payload(st, u, dev, typ, content) {
                msgs.entry(u.clone()).or_insert_with(|| json!({}))[d] = c;
                n += 1;
            }
        }
        if n == 0 {
            return Err(format!("no Olm session for {typ}"));
        }
        self.save(st).map_err(|e| e.to_string())?;
        call("PUT", &format!("/_matrix/client/v3/sendToDevice/m.room.encrypted/{}", enc(&format!("ark-td-{}", ark_net::crypto::random_token(9)))), json!({"messages": msgs})).map_err(|e| e.to_string())?;
        Ok(n)
    }

    /// Unwedge a broken Olm channel: a fresh session and an `m.dummy` (once an hour per device).
    fn unwedge(&self, st: &mut Store, sender: &str, sender_key: &str, call: Call) {
        let now = now_ms();
        if st.dummy_sent.get(sender_key).is_some_and(|t| now.saturating_sub(*t) < UNWEDGE_EVERY_MS) {
            return;
        }
        let Some((dev, d)) = self.device_by_curve(st, sender, sender_key, call) else { return };
        if self.distrust(st, sender, &dev, &d).is_some() {
            return;
        }
        st.dummy_sent.insert(sender_key.to_string(), now);
        let to = [(sender.to_string(), dev.clone(), d)];
        let r = self.claim(st, &to, true, call).map_err(|e| e.to_string()).and_then(|_| self.send_olm(st, &to, "m.dummy", &json!({}), call));
        match r {
            Ok(_) => eprintln!("matrix {}: Olm session with {sender} {dev} was wedged; sent m.dummy on a new session", self.label),
            Err(e) => eprintln!("matrix {}: unwedging {sender} {dev}: {e}", self.label),
        }
    }

    /// Our own device asks for a Megolm session: answer verified devices only.
    fn on_key_request(&self, st: &mut Store, sender: &str, c: &Value, call: Call) -> Result<(), String> {
        let dev = s(&c["requesting_device_id"]);
        if c["action"] != "request" || sender != st.user_id || dev == st.device_id {
            return Ok(());
        }
        let b = &c["body"];
        let id = format!("{}\n{}", s(&b["room_id"]), s(&b["session_id"]));
        let Some(rec) = st.inbound.get(&id).filter(|r| !r.sender.is_empty()) else { return Ok(()) };
        let content = json!({"algorithm": MEGOLM, "room_id": b["room_id"], "sender_key": rec.sender_key, "session_id": b["session_id"], "session_key": rec.session.export(),
            "sender_claimed_ed25519_key": rec.claimed_ed25519, "forwarding_curve25519_key_chain": rec.chain});
        if Self::own_verified(st, dev).is_none() {
            st.outdated.insert(st.user_id.clone());
            let me = st.user_id.clone();
            self.ensure_devices(st, &[me], call).map_err(|e| e.to_string())?;
        }
        let d = Self::own_verified(st, dev).ok_or_else(|| format!("key request from our unverified device {dev}; ignored"))?;
        self.send_olm(st, &[(st.user_id.clone(), dev.to_string(), d)], "m.forwarded_room_key", &content, call).map(|_| ())
    }

    /// A forwarded session: only one we asked for, from our own verified device or the session's own device.
    fn on_forwarded_key(&self, st: &mut Store, from: &str, from_d: &Device, c: &Value, call: Call) -> Result<(), String> {
        let (room, sid, sender_key) = (s(&c["room_id"]), s(&c["session_id"]), s(&c["sender_key"]));
        let req = st.requested.get(&format!("{room}\n{sid}")).cloned().ok_or("m.forwarded_room_key we did not ask for")?;
        let own = from == st.user_id && st.devices.get(from).is_some_and(|m| m.iter().any(|(k, d)| d.curve25519 == from_d.curve25519 && Self::own_verified(st, k).is_some()));
        if !own && !(from == req.sender && from_d.curve25519 == sender_key) {
            return Err("forwarded key from a device not trusted for it".into());
        }
        if c["algorithm"] != MEGOLM {
            return Err(format!("unsupported room key algorithm {}", c["algorithm"]));
        }
        let g = GroupInbound::from_session_key(s(&c["session_key"])).map_err(|e| e.to_string())?;
        if g.id() != sid {
            return Err("session_id does not match session_key".into());
        }
        if self.device_by_curve(st, &req.sender, sender_key, call).is_none() {
            return Err(format!("sender_key is not a device of {}", req.sender));
        }
        let mut chain: Vec<String> = c["forwarding_curve25519_key_chain"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
        chain.push(from_d.curve25519.clone());
        let rec = InboundRec { session: g, sender: req.sender.clone(), sender_key: sender_key.into(), seen: BTreeMap::new(), claimed_ed25519: s(&c["sender_claimed_ed25519_key"]).into(), chain, backed_up: false };
        self.add_inbound(st, room, rec, call);
        Ok(())
    }

    /// An event whose session we lack: try the key backup, else ask our devices and the
    /// sender's device (once per session). `true` = the session is here now.
    pub fn on_missing(&self, room: &str, ev: &Value, call: Call) -> bool {
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        let (c, sender) = (&ev["content"], s(&ev["sender"]));
        let sid = s(&c["session_id"]);
        let id = format!("{room}\n{sid}");
        if st.inbound.contains_key(&id) || sid.is_empty() {
            return st.inbound.contains_key(&id);
        }
        let now = now_ms();
        st.requested.retain(|_, r| now.saturating_sub(r.ms) < KEY_REQUEST_TTL_MS);
        if st.requested.contains_key(&id) {
            return false;
        }
        if self.restore_session(st, room, sid, sender, call) {
            let _ = self.save(st);
            return true;
        }
        let req = KeyRequest { id: format!("ark-kr-{}", ark_net::crypto::random_token(9)), sender: sender.into(), ms: now };
        let body = json!({"action": "request", "body": {"algorithm": MEGOLM, "room_id": room, "sender_key": c["sender_key"], "session_id": sid}, "request_id": req.id, "requesting_device_id": st.device_id});
        let mut msgs = json!({ st.user_id.clone(): {"*": body} });
        if let Some(d) = c["device_id"].as_str().filter(|_| sender != st.user_id) {
            msgs[sender] = json!({ d: body });
        }
        st.requested.insert(id, req);
        self.mem.lock().unwrap().dirty = true;
        if let Err(e) = call("PUT", &format!("/_matrix/client/v3/sendToDevice/m.room_key_request/{}", enc(&format!("ark-kr-{}", ark_net::crypto::random_token(9)))), json!({"messages": msgs})) {
            eprintln!("matrix {}: m.room_key_request: {e}", self.label);
        }
        false
    }

    /// Decrypt a Megolm `m.room.encrypted` timeline event into the plaintext event.
    pub fn decrypt_room(&self, room: &str, ev: &Value) -> Result<Value, DecryptError> {
        let c = &ev["content"];
        if c["algorithm"] != MEGOLM {
            return Err(DecryptError::Rejected(format!("unsupported algorithm {}", c["algorithm"])));
        }
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        let id = format!("{room}\n{}", s(&c["session_id"]));
        let (owner, key) = st.inbound.get(&id).map(|r| (r.sender.clone(), r.sender_key.clone())).ok_or(DecryptError::MissingSession)?;
        let sender = s(&ev["sender"]);
        if owner != sender {
            return Err(DecryptError::Rejected(format!("session belongs to {owner}, not {sender}")));
        }
        if let Some((dev, d)) = st.devices.get(sender).and_then(|m| m.iter().find(|(_, d)| d.curve25519 == key)) {
            if let Some(why) = self.distrust(st, sender, dev, d) {
                return Err(DecryptError::Rejected(format!("device {dev}: {why}")));
            }
        }
        let rec = st.inbound.get_mut(&id).unwrap();
        let (plain, index) = rec.session.decrypt(s(&c["ciphertext"])).map_err(|e| match e {
            OlmError::UnknownIndex => DecryptError::Rejected("message index precedes our session".into()),
            e => DecryptError::Rejected(e.to_string()),
        })?;
        let eid = s(&ev["event_id"]);
        match rec.seen.get(&index) {
            Some(prev) if prev != eid => return Err(DecryptError::Rejected(format!("replayed message index {index} (first seen in {prev})"))),
            Some(_) => {}
            None => {
                rec.seen.insert(index, eid.to_string());
                if rec.seen.len() > MAX_SEEN_PER_SESSION {
                    rec.seen.pop_first();
                }
                self.mem.lock().unwrap().dirty = true;
            }
        }
        let p: Value = serde_json::from_slice(&plain).map_err(|_| DecryptError::Rejected("plaintext is not JSON".into()))?;
        if p["room_id"] != room {
            return Err(DecryptError::Rejected("room_id mismatch".into()));
        }
        let mut out = ev.clone();
        out["type"] = p["type"].clone();
        out["content"] = p["content"].clone();
        if out["content"].get("m.relates_to").is_none() && c.get("m.relates_to").is_some() && out["content"].is_object() {
            out["content"]["m.relates_to"] = c["m.relates_to"].clone();
        }
        if let Some(f) = out["content"]["file"].as_object().filter(|f| f.get("url").is_some()) {
            let url = s(&f["url"]).to_string();
            st.files.retain(|(u, _)| *u != url);
            st.files.push((url, Value::Object(f.clone())));
            let extra = st.files.len().saturating_sub(MAX_FILES);
            st.files.drain(..extra);
            self.mem.lock().unwrap().dirty = true;
        }
        Ok(out)
    }

    /// `EncryptedFile` for an mxc url seen in a decrypted event.
    pub fn file_for(&self, mxc: &str) -> Option<Value> {
        self.st.lock().unwrap().files.iter().rev().find(|(u, _)| u == mxc).map(|(_, f)| f.clone())
    }

    /// Joined members, plus invited ones unless `history_visibility` is `joined`.
    fn members(&self, room: &str, call: Call) -> Result<Vec<String>, ChannelError> {
        if let Some(m) = self.mem.lock().unwrap().members.get(room) {
            return Ok(m.clone());
        }
        let r = call("GET", &format!("/_matrix/client/v3/rooms/{}/joined_members", enc(room)), Value::Null)?;
        let mut m: Vec<String> = r["joined"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        let known = self.mem.lock().unwrap().visibility.get(room).cloned();
        let vis = match known {
            Some(v) => v,
            None => {
                let v = match call("GET", &format!("/_matrix/client/v3/rooms/{}/state/m.room.history_visibility/", enc(room)), Value::Null) {
                    Ok(v) => s(&v["history_visibility"]).to_string(),
                    Err(e) if e.kind == K::NotFound => String::new(),
                    Err(e) => return Err(e),
                };
                let v = if v.is_empty() { "shared".to_string() } else { v };
                self.mem.lock().unwrap().visibility.insert(room.to_string(), v.clone());
                v
            }
        };
        if vis != "joined" {
            if let Ok(r) = call("GET", &format!("/_matrix/client/v3/rooms/{}/members?membership=invite", enc(room)), Value::Null) {
                for e in r["chunk"].as_array().into_iter().flatten().filter(|e| e["content"]["membership"] == "invite") {
                    let u = s(&e["state_key"]).to_string();
                    if !u.is_empty() && !m.contains(&u) {
                        m.push(u);
                    }
                }
            }
        }
        self.mem.lock().unwrap().members.insert(room.to_string(), m.clone());
        Ok(m)
    }

    pub(crate) fn olm_payload(st: &mut Store, user: &str, d: &Device, typ: &str, content: &Value) -> Option<Value> {
        let p = json!({"type": typ, "content": content, "sender": st.user_id, "sender_device": st.device_id, "keys": {"ed25519": st.account.ed25519()}, "recipient": user, "recipient_keys": {"ed25519": d.ed25519}});
        let s = st.sessions.get_mut(&d.curve25519)?.iter_mut().max_by_key(|s| s.last_used)?;
        let (t, body) = s.encrypt(p.to_string().as_bytes());
        s.last_used = now_ms();
        Some(json!({"algorithm": OLM, "sender_key": st.account.curve25519(), "ciphertext": { d.curve25519.clone(): {"type": t, "body": b64(&body)} }}))
    }

    /// Claim one-time keys and open Olm sessions for devices we have none with
    /// (`force`: a new session even if we have one).
    pub(crate) fn claim(&self, st: &mut Store, devs: &[(String, String, Device)], force: bool, call: Call) -> Result<(), ChannelError> {
        let mem = self.mem.lock().unwrap();
        let missing: Vec<&(String, String, Device)> = devs.iter().filter(|(u, d, dev)| (force || st.sessions.get(&dev.curve25519).is_none_or(|v| v.is_empty())) && mem.no_key.get(&format!("{u} {d}")).is_none_or(|t| t.elapsed() > NO_KEY_RETRY)).collect();
        if missing.is_empty() {
            return Ok(());
        }
        let mut q = serde_json::Map::new();
        for (u, d, _) in &missing {
            q.entry(u.clone()).or_insert_with(|| json!({}))[d] = json!("signed_curve25519");
        }
        drop(mem);
        let r = call("POST", "/_matrix/client/v3/keys/claim", json!({"one_time_keys": q, "timeout": 10000}))?;
        let mut mem = self.mem.lock().unwrap();
        for (u, d, dev) in missing {
            let got = r["one_time_keys"][u][d].as_object().and_then(|o| o.iter().find(|(k, _)| k.starts_with("signed_curve25519:")));
            let otk = got.filter(|(_, v)| verify_json(v, u, &format!("ed25519:{d}"), &dev.ed25519)).and_then(|(_, v)| key32(s(&v["key"])));
            match (otk, key32(&dev.curve25519)) {
                (Some(otk), Some(identity)) => {
                    let mut s = st.account.outbound_session(&identity, &otk);
                    s.last_used = now_ms();
                    st.sessions.entry(dev.curve25519.clone()).or_default().push(s);
                    mem.no_key.remove(&format!("{u} {d}"));
                }
                _ => {
                    eprintln!("matrix {}: no valid one-time key for {u} {d}; it will not get room keys for now", self.label);
                    mem.no_key.insert(format!("{u} {d}"), Instant::now());
                }
            }
        }
        Ok(())
    }

    /// Encrypt one room event (`settings` = the room's `m.room.encryption` content),
    /// sharing the room key first with every member device that lacks it.
    pub fn encrypt_room(&self, room: &str, settings: &Value, typ: &str, content: &Value, call: Call) -> Result<Value, ChannelError> {
        if settings["algorithm"] != MEGOLM {
            return Err(fatal(format!("matrix room {room} uses unsupported encryption {}", settings["algorithm"])));
        }
        let members = self.members(room, call)?;
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        self.ensure_devices(st, &members, call)?;
        let recipients: Vec<(String, String, Device)> = members
            .iter()
            .flat_map(|u| st.devices.get(u).into_iter().flatten().map(move |(d, dev)| (u.clone(), d.clone(), dev.clone())))
            .filter(|(u, d, dev)| !(*u == st.user_id && *d == st.device_id) && self.distrust(st, u, d, dev).is_none())
            .collect();
        let keys: BTreeSet<String> = recipients.iter().map(|(u, d, _)| format!("{u} {d}")).collect();
        let period = settings["rotation_period_ms"].as_u64().unwrap_or(604_800_000);
        let max_msgs = settings["rotation_period_msgs"].as_u64().unwrap_or(100).max(1);
        let mut o = match st.outbound.remove(room) {
            Some(o) if now_ms().saturating_sub(o.created_ms) < period && o.messages < max_msgs && o.shared.is_subset(&keys) => o,
            _ => {
                let o = OutboundRec { session: GroupOutbound::generate(), created_ms: now_ms(), messages: 0, shared: BTreeSet::new() };
                // Our own copy: for our other devices (key requests) and the key backup.
                if let Ok(g) = GroupInbound::from_session_key(&o.session.session_key()) {
                    let (me, curve, ed) = (st.user_id.clone(), st.account.curve25519(), st.account.ed25519());
                    st.inbound.insert(format!("{room}\n{}", g.id()), InboundRec { session: g, sender: me, sender_key: curve, seen: BTreeMap::new(), claimed_ed25519: ed, chain: vec![], backed_up: false });
                }
                o
            }
        };
        let need: Vec<(String, String, Device)> = recipients.into_iter().filter(|(u, d, _)| !o.shared.contains(&format!("{u} {d}"))).collect();
        if !need.is_empty() {
            let r = self.claim(st, &need, false, call);
            if let Err(e) = r {
                st.outbound.insert(room.to_string(), o);
                return Err(e);
            }
            let key = json!({"algorithm": MEGOLM, "room_id": room, "session_id": o.session.id(), "session_key": o.session.session_key()});
            let mut msgs = serde_json::Map::new();
            let mut sent = vec![];
            for (u, d, dev) in &need {
                if let Some(c) = Self::olm_payload(st, u, dev, "m.room_key", &key) {
                    msgs.entry(u.clone()).or_insert_with(|| json!({}))[d] = c;
                    sent.push(format!("{u} {d}"));
                }
            }
            if !msgs.is_empty() {
                let txn = format!("ark-td-{}", ark_net::crypto::random_token(9));
                // Olm ratchets advanced: persist before the network call.
                self.save(st)?;
                if let Err(e) = call("PUT", &format!("/_matrix/client/v3/sendToDevice/m.room.encrypted/{}", enc(&txn)), json!({"messages": msgs})) {
                    st.outbound.insert(room.to_string(), o);
                    return Err(e);
                }
                o.shared.extend(sent);
            }
        }
        let plain = json!({"type": typ, "content": content, "room_id": room});
        let ciphertext = o.session.encrypt(plain.to_string().as_bytes());
        o.messages += 1;
        let mut out = json!({"algorithm": MEGOLM, "sender_key": st.account.curve25519(), "device_id": st.device_id, "session_id": o.session.id(), "ciphertext": ciphertext});
        if let Some(r) = content.get("m.relates_to") {
            out["m.relates_to"] = r.clone();
        }
        st.outbound.insert(room.to_string(), o);
        self.save(st)?;
        self.backup_pending(st, call);
        Ok(out)
    }
}

/// Encrypt attachment bytes: (ciphertext, `EncryptedFile` without `url`).
pub fn encrypt_attachment(data: &[u8]) -> (Vec<u8>, Value) {
    let key: [u8; 32] = random_bytes(32).try_into().unwrap();
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&random_bytes(8));
    let mut ct = data.to_vec();
    Aes::new(&key).unwrap().ctr_apply(&iv, &mut ct);
    let file = json!({"v": "v2", "key": {"kty": "oct", "key_ops": ["encrypt", "decrypt"], "alg": "A256CTR", "k": ark_net::crypto::b64url(&key), "ext": true}, "iv": b64(&iv), "hashes": {"sha256": b64(&sha256(&ct))}});
    (ct, file)
}

/// Verify the SHA-256 and decrypt an `EncryptedFile` download.
pub fn decrypt_attachment(data: &[u8], file: &Value) -> Result<Vec<u8>, ChannelError> {
    let k = &file["key"];
    if k["alg"] != "A256CTR" || k["kty"] != "oct" {
        return Err(ChannelError::new(K::Protocol, "matrix encrypted file: unsupported key"));
    }
    let key = ark_net::crypto::b64url_decode(s(&k["k"])).filter(|k| k.len() == 32).ok_or_else(|| ChannelError::new(K::Protocol, "matrix encrypted file: bad key"))?;
    let iv: [u8; 16] = unb64(s(&file["iv"])).and_then(|v| v.try_into().ok()).ok_or_else(|| ChannelError::new(K::Protocol, "matrix encrypted file: bad iv"))?;
    let want = unb64(s(&file["hashes"]["sha256"])).ok_or_else(|| ChannelError::new(K::Protocol, "matrix encrypted file: no sha256"))?;
    if !ark_net::crypto::ct_eq(&sha256(data), &want) {
        return Err(ChannelError::new(K::Protocol, "matrix encrypted file: sha256 mismatch"));
    }
    let mut out = data.to_vec();
    Aes::new(&key).unwrap().ctr_apply(&iv, &mut out);
    Ok(out)
}

/// In-memory homeserver for the E2EE endpoints (unit tests here and the
/// two-device round trip in `matrix`).
#[cfg(test)]
pub(crate) mod fake_hs {
    use super::*;
    use std::collections::VecDeque;

    /// (version info, room → session → backed-up data).
    type Backup = (Value, BTreeMap<String, BTreeMap<String, Value>>);

    #[derive(Default)]
    struct St {
        keys: HashMap<String, serde_json::Map<String, Value>>,
        otks: HashMap<String, BTreeMap<String, Value>>,
        fallback: HashMap<String, Value>,
        fallback_used: BTreeSet<String>,
        todev: HashMap<String, VecDeque<Value>>,
        changed: HashMap<String, Vec<String>>,
        timeline: Vec<Value>,
        cursor: HashMap<String, usize>,
        media: Vec<Vec<u8>>,
        /// user → (master, self_signing, user_signing) key objects.
        cross: HashMap<String, (Value, Value, Value)>,
        account_data: HashMap<(String, String), Value>,
        /// Per user, backup versions: (algorithm/auth_data, room → session → data).
        backups: HashMap<String, Vec<Backup>>,
    }

    pub struct FakeHs {
        st: Mutex<St>,
        pub room: String,
        pub members: Mutex<Vec<String>>,
        pub encryption: Value,
        /// Hold back to-device messages (keys arriving after their events).
        pub hold: std::sync::atomic::AtomicBool,
        pub invited: Mutex<Vec<String>>,
        /// Every to-device message sent, as `(type, sender, recipient user, content)`.
        pub sent_todev: Mutex<Vec<(String, String, String, Value)>>,
    }

    fn q(u: &str, d: &str) -> String {
        format!("{u}|{d}")
    }

    impl FakeHs {
        pub fn new(room: &str, members: &[&str], encryption: Value) -> FakeHs {
            FakeHs { st: Mutex::default(), room: room.into(), members: Mutex::new(members.iter().map(|m| m.to_string()).collect()), encryption, hold: Default::default(), invited: Mutex::default(), sent_todev: Mutex::default() }
        }

        pub fn call_as<'a>(&'a self, user: &'a str, dev: &'a str) -> impl Fn(&str, &str, Value) -> Result<Value, ChannelError> + 'a {
            move |m, p, b| self.handle(user, dev, m, p, &b)
        }

        pub fn upload_media(&self, data: Vec<u8>) -> String {
            let mut st = self.st.lock().unwrap();
            st.media.push(data);
            format!("mxc://hs.test/{}", st.media.len() - 1)
        }

        pub fn media(&self, id: usize) -> Option<Vec<u8>> {
            self.st.lock().unwrap().media.get(id).cloned()
        }

        /// Raw (encrypted) room events as the server stores them.
        pub fn timeline(&self) -> Vec<Value> {
            self.st.lock().unwrap().timeline.clone()
        }

        /// Pretend a device's keys changed on the server (for TOFU tests).
        pub fn mark_changed(&self, user: &str) {
            let mut st = self.st.lock().unwrap();
            let all: Vec<String> = self.members.lock().unwrap().clone();
            for m in all {
                st.changed.entry(m).or_default().push(user.into());
            }
        }

        pub fn account_data(&self, user: &str, typ: &str) -> Option<Value> {
            self.st.lock().unwrap().account_data.get(&(user.to_string(), typ.to_string())).cloned()
        }

        pub fn backup(&self, user: &str, room: &str, session: &str) -> Option<Value> {
            self.st.lock().unwrap().backups.get(user)?.last().and_then(|(_, b)| b.get(room)?.get(session).cloned())
        }

        pub fn otk_count(&self, user: &str, dev: &str) -> usize {
            self.st.lock().unwrap().otks.get(&q(user, dev)).map_or(0, |m| m.len())
        }

        pub fn handle(&self, user: &str, dev: &str, method: &str, path: &str, b: &Value) -> Result<Value, ChannelError> {
            let mut st = self.st.lock().unwrap();
            let (p, query) = path.split_once('?').unwrap_or((path, ""));
            let seg: Vec<String> = p.split('/').map(ark_net::urldecode).collect();
            Ok(match (method, p) {
                ("POST", "/_matrix/client/v3/keys/upload") => {
                    if b["device_keys"].is_object() {
                        st.keys.entry(user.into()).or_default().insert(dev.into(), b["device_keys"].clone());
                    }
                    let k = q(user, dev);
                    for (id, v) in b["one_time_keys"].as_object().into_iter().flatten() {
                        st.otks.entry(k.clone()).or_default().insert(id.clone(), v.clone());
                    }
                    if let Some(f) = b["fallback_keys"].as_object().filter(|f| !f.is_empty()) {
                        st.fallback.insert(k.clone(), Value::Object(f.clone()));
                        st.fallback_used.remove(&k);
                    }
                    json!({"one_time_key_counts": {"signed_curve25519": st.otks.get(&k).map_or(0, |m| m.len())}})
                }
                ("POST", "/_matrix/client/v3/keys/query") => {
                    let out: serde_json::Map<String, Value> = b["device_keys"].as_object().into_iter().flatten().map(|(u, _)| (u.clone(), Value::Object(st.keys.get(u).cloned().unwrap_or_default()))).collect();
                    let mut r = json!({"device_keys": out, "failures": {}, "master_keys": {}, "self_signing_keys": {}, "user_signing_keys": {}});
                    for u in b["device_keys"].as_object().into_iter().flatten().map(|(u, _)| u) {
                        if let Some((m, ss, us)) = st.cross.get(u) {
                            r["master_keys"][u] = m.clone();
                            r["self_signing_keys"][u] = ss.clone();
                            if u == user {
                                r["user_signing_keys"][u] = us.clone();
                            }
                        }
                    }
                    r
                }
                ("POST", "/_matrix/client/v3/keys/device_signing/upload") => {
                    st.cross.insert(user.into(), (b["master_key"].clone(), b["self_signing_key"].clone(), b["user_signing_key"].clone()));
                    json!({})
                }
                ("POST", "/_matrix/client/v3/keys/signatures/upload") => {
                    for (u, objs) in b.as_object().into_iter().flatten() {
                        for (id, obj) in objs.as_object().into_iter().flatten() {
                            let merge = |target: &mut Value| {
                                for (su, sigs) in obj["signatures"].as_object().into_iter().flatten() {
                                    for (k, v) in sigs.as_object().into_iter().flatten() {
                                        target["signatures"][su][k] = v.clone();
                                    }
                                }
                            };
                            if let Some(d) = st.keys.get_mut(u).and_then(|m| m.get_mut(id)) {
                                merge(d);
                            } else if let Some(c) = st.cross.get_mut(u).filter(|c| c.0["keys"][format!("ed25519:{id}")].is_string()) {
                                merge(&mut c.0);
                            }
                        }
                    }
                    let mut changed = vec![];
                    for (u, _) in b.as_object().into_iter().flatten() {
                        changed.push(u.clone());
                    }
                    for m in self.members.lock().unwrap().iter() {
                        st.changed.entry(m.clone()).or_default().extend(changed.iter().cloned());
                    }
                    json!({"failures": {}})
                }
                (_, _) if seg.len() == 8 && seg[4] == "user" && seg[6] == "account_data" => {
                    let k = (seg[5].clone(), seg[7].clone());
                    if method == "PUT" {
                        st.account_data.insert(k, b.clone());
                        json!({})
                    } else {
                        return st.account_data.get(&k).cloned().ok_or_else(|| ChannelError::new(K::NotFound, "M_NOT_FOUND"));
                    }
                }
                ("GET", "/_matrix/client/v3/room_keys/version") => {
                    let all = st.backups.get(user).filter(|v| !v.is_empty()).ok_or_else(|| ChannelError::new(K::NotFound, "M_NOT_FOUND"))?;
                    let mut v = all.last().unwrap().0.clone();
                    v["version"] = json!(all.len().to_string());
                    v
                }
                ("POST", "/_matrix/client/v3/room_keys/version") => {
                    let all = st.backups.entry(user.into()).or_default();
                    all.push((b.clone(), BTreeMap::new()));
                    json!({"version": all.len().to_string()})
                }
                ("PUT", "/_matrix/client/v3/room_keys/keys") => {
                    let all = st.backups.entry(user.into()).or_default();
                    if all.is_empty() || query != format!("version={}", all.len()) {
                        return Err(ChannelError::new(K::NotFound, "M_WRONG_ROOM_KEYS_VERSION"));
                    }
                    let last = all.last_mut().unwrap();
                    for (room, r) in b["rooms"].as_object().into_iter().flatten() {
                        for (sid, d) in r["sessions"].as_object().into_iter().flatten() {
                            last.1.entry(room.clone()).or_default().insert(sid.clone(), d.clone());
                        }
                    }
                    json!({"count": 1, "etag": "1"})
                }
                ("GET", _) if p.starts_with("/_matrix/client/v3/room_keys/keys/") => {
                    return st.backups.get(user).and_then(|v| v.last()).and_then(|(_, b)| b.get(&seg[6])?.get(&seg[7]).cloned()).ok_or_else(|| ChannelError::new(K::NotFound, "M_NOT_FOUND"));
                }
                ("GET", _) if p.ends_with("/members") && query.contains("membership=invite") => {
                    json!({"chunk": self.invited.lock().unwrap().iter().map(|u| json!({"type": "m.room.member", "state_key": u, "content": {"membership": "invite"}})).collect::<Vec<_>>()})
                }
                ("POST", "/_matrix/client/v3/keys/claim") => {
                    let mut out = json!({});
                    for (u, devs) in b["one_time_keys"].as_object().into_iter().flatten() {
                        for d in devs.as_object().into_iter().flatten().map(|(d, _)| d) {
                            let k = q(u, d);
                            let got = st.otks.get_mut(&k).and_then(|m| m.pop_first()).map(|(id, v)| json!({ id: v }));
                            let got = got.or_else(|| {
                                st.fallback_used.insert(k.clone());
                                st.fallback.get(&k).cloned()
                            });
                            if let Some(g) = got {
                                out[u][d] = g;
                            }
                        }
                    }
                    json!({"one_time_keys": out, "failures": {}})
                }
                ("PUT", _) if p.starts_with("/_matrix/client/v3/sendToDevice/") => {
                    for (u, devs) in b["messages"].as_object().into_iter().flatten() {
                        for (d, c) in devs.as_object().into_iter().flatten() {
                            self.sent_todev.lock().unwrap().push((seg[5].clone(), user.into(), u.clone(), c.clone()));
                            let targets: Vec<String> = if d == "*" { st.keys.get(u).map(|m| m.keys().filter(|k| !(u == user && *k == dev)).cloned().collect()).unwrap_or_default() } else { vec![d.clone()] };
                            for d in targets {
                                st.todev.entry(q(u, &d)).or_default().push_back(json!({"type": seg[5], "sender": user, "content": c}));
                            }
                        }
                    }
                    json!({})
                }
                ("GET", _) if p.ends_with("/joined_members") => json!({"joined": self.members.lock().unwrap().iter().map(|m| (m.clone(), json!({}))).collect::<serde_json::Map<_, _>>()}),
                ("GET", _) if p.ends_with("/state/m.room.encryption/") => {
                    if seg[5] == self.room {
                        self.encryption.clone()
                    } else {
                        return Err(ChannelError::new(K::NotFound, "M_NOT_FOUND"));
                    }
                }
                ("PUT", _) if p.contains("/send/") || p.contains("/redact/") => {
                    let typ = if p.contains("/redact/") { "m.room.redaction".to_string() } else { seg[7].clone() };
                    let id = format!("$ev{}", st.timeline.len());
                    st.timeline.push(json!({"type": typ, "sender": user, "content": b, "event_id": id, "origin_server_ts": 1_700_000_000_000i64, "room_id": seg[5]}));
                    json!({"event_id": id})
                }
                ("GET", "/_matrix/client/v3/sync") => {
                    let k = q(user, dev);
                    let first = !query.contains("since=");
                    let from = *st.cursor.get(&k).unwrap_or(&0);
                    let events: Vec<Value> = st.timeline[from..].to_vec();
                    let len = st.timeline.len();
                    st.cursor.insert(k.clone(), len);
                    let td: Vec<Value> = if self.hold.load(std::sync::atomic::Ordering::SeqCst) { vec![] } else { st.todev.remove(&k).unwrap_or_default().into() };
                    let changed = st.changed.remove(user).unwrap_or_default();
                    let mut room = json!({"summary": {"m.joined_member_count": self.members.lock().unwrap().len()}, "timeline": {"events": events}});
                    if first {
                        room["state"] = json!({"events": [{"type": "m.room.encryption", "state_key": "", "content": self.encryption}]});
                    }
                    let unused: Vec<&str> = if st.fallback_used.contains(&k) { vec![] } else { vec!["signed_curve25519"] };
                    json!({"next_batch": format!("s{len}"), "to_device": {"events": td}, "device_lists": {"changed": changed, "left": []},
                        "device_one_time_keys_count": {"signed_curve25519": st.otks.get(&k).map_or(0, |m| m.len())}, "device_unused_fallback_key_types": unused,
                        "rooms": {"join": { self.room.clone(): room }}})
                }
                ("GET", "/_matrix/client/v3/account/whoami") => json!({"user_id": user, "device_id": dev}),
                _ => json!({}),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake_hs::FakeHs;
    use super::*;
    use crate::testutil::temp_dir;

    const ROOM: &str = "!r:hs.test";
    const A: &str = "@a:hs.test";
    const B: &str = "@b:hs.test";
    const C: &str = "@c:hs.test";

    fn dev(hs: &FakeHs, dir: &Path, user: &'static str, d: &'static str) -> E2ee {
        let e = E2ee::open(user, &dir.join(format!("{d}.e2ee")), None, user, d).unwrap();
        e.ensure_uploaded(&hs.call_as(user, d)).unwrap();
        e
    }

    fn sync(hs: &FakeHs, e: &E2ee, user: &'static str, d: &'static str) -> Value {
        let call = hs.call_as(user, d);
        let v = call("GET", "/_matrix/client/v3/sync?since=x", Value::Null).unwrap();
        e.on_sync(&v, &call);
        v
    }

    fn send(hs: &FakeHs, e: &E2ee, user: &'static str, d: &'static str, body: &str) -> Value {
        let call = hs.call_as(user, d);
        let c = e.encrypt_room(ROOM, &hs.encryption, "m.room.message", &json!({"msgtype": "m.text", "body": body}), &call).unwrap();
        let id = call("PUT", &format!("/_matrix/client/v3/rooms/{}/send/m.room.encrypted/t", enc(ROOM)), c.clone()).unwrap();
        json!({"type": "m.room.encrypted", "sender": user, "event_id": id["event_id"], "content": c})
    }

    fn body(r: Result<Value, DecryptError>) -> String {
        s(&r.unwrap()["content"]["body"]).to_string()
    }

    #[test]
    fn keys_are_signed_and_room_keys_flow_over_olm() {
        let hs = FakeHs::new(ROOM, &[A, B], json!({"algorithm": MEGOLM, "rotation_period_msgs": 3}));
        let dir = temp_dir("e2ee");
        let (a, b) = (dev(&hs, &dir, A, "ADEV"), dev(&hs, &dir, B, "BDEV"));
        // Uploaded device keys are self-signed; one-time keys signed by the device.
        let q = hs.call_as(A, "ADEV")("POST", "/_matrix/client/v3/keys/query", json!({"device_keys": {B: []}})).unwrap();
        let k = &q["device_keys"][B]["BDEV"];
        assert!(verify_json(k, B, "ed25519:BDEV", s(&k["keys"]["ed25519:BDEV"])));
        assert_eq!(k["keys"]["curve25519:BDEV"], b.identity().1);
        assert_eq!(hs.otk_count(B, "BDEV"), 50);
        let e1 = send(&hs, &a, A, "ADEV", "one");
        assert_eq!(hs.otk_count(B, "BDEV"), 49, "a claimed one of b's keys");
        assert_eq!(b.decrypt_room(ROOM, &e1), Err(DecryptError::MissingSession), "key not synced yet");
        sync(&hs, &b, B, "BDEV");
        assert_eq!(hs.otk_count(B, "BDEV"), 50, "b replenished its one-time keys");
        assert_eq!(body(b.decrypt_room(ROOM, &e1)), "one");
        assert_eq!(body(b.decrypt_room(ROOM, &e1)), "one", "the same event again is fine");
        let mut replay = e1.clone();
        replay["event_id"] = json!("$other");
        assert!(matches!(b.decrypt_room(ROOM, &replay), Err(DecryptError::Rejected(e)) if e.contains("replayed")));
        let mut forged = e1.clone();
        forged["sender"] = json!(C);
        assert!(matches!(b.decrypt_room(ROOM, &forged), Err(DecryptError::Rejected(e)) if e.contains("belongs to")));
        assert!(matches!(b.decrypt_room("!elsewhere:hs.test", &e1), Err(DecryptError::MissingSession)), "sessions are per room");
        // Same session for the next messages (no new to-device), and b answers over Olm.
        let e2 = send(&hs, &a, A, "ADEV", "two");
        assert_eq!(e2["content"]["session_id"], e1["content"]["session_id"]);
        let r1 = send(&hs, &b, B, "BDEV", "reply");
        sync(&hs, &a, A, "ADEV");
        assert_eq!(body(a.decrypt_room(ROOM, &r1)), "reply");
        assert_eq!(body(b.decrypt_room(ROOM, &e2)), "two");
        // rotation_period_msgs = 3: the fourth message starts a new session.
        let e3 = send(&hs, &a, A, "ADEV", "three");
        let e4 = send(&hs, &a, A, "ADEV", "four");
        assert_eq!(e3["content"]["session_id"], e1["content"]["session_id"]);
        assert_ne!(e4["content"]["session_id"], e1["content"]["session_id"]);
        sync(&hs, &b, B, "BDEV");
        assert_eq!((body(b.decrypt_room(ROOM, &e3)), body(b.decrypt_room(ROOM, &e4))), ("three".into(), "four".into()));
        // A member leaving rotates the session.
        let leave = json!({"rooms": {"join": {ROOM: {"timeline": {"events": [{"type": "m.room.member", "state_key": C, "content": {"membership": "leave"}}]}}}}});
        a.on_sync(&leave, &hs.call_as(A, "ADEV"));
        assert_ne!(send(&hs, &a, A, "ADEV", "five")["content"]["session_id"], e4["content"]["session_id"]);
        // Fallback key: used up → rotated and re-uploaded.
        for _ in 0..60 {
            hs.call_as(A, "ADEV")("POST", "/_matrix/client/v3/keys/claim", json!({"one_time_keys": {B: {"BDEV": "signed_curve25519"}}})).unwrap();
        }
        let v = sync(&hs, &b, B, "BDEV");
        assert_eq!(v["device_unused_fallback_key_types"], json!([]));
        assert_eq!(sync(&hs, &b, B, "BDEV")["device_unused_fallback_key_types"], json!(["signed_curve25519"]), "new fallback key uploaded");
    }

    #[test]
    fn tofu_blacklist_and_store() {
        let hs = FakeHs::new(ROOM, &[A, B, C], json!({"algorithm": MEGOLM}));
        let dir = temp_dir("e2ee");
        let (mut a, b, c) = (dev(&hs, &dir, A, "ADEV"), dev(&hs, &dir, B, "BDEV"), dev(&hs, &dir, C, "CDEV"));
        a.blacklist = vec![format!("{C}/CDEV")];
        let e1 = send(&hs, &a, A, "ADEV", "secret");
        sync(&hs, &b, B, "BDEV");
        sync(&hs, &c, C, "CDEV");
        assert_eq!(body(b.decrypt_room(ROOM, &e1)), "secret");
        assert_eq!(c.decrypt_room(ROOM, &e1), Err(DecryptError::MissingSession), "blacklisted device got no key");
        // B's device id comes back with new identity keys (e.g. a hijacked device): blocked.
        let b2 = E2ee::open(B, &dir.join("B2.e2ee"), None, B, "BDEV").unwrap();
        b2.ensure_uploaded(&hs.call_as(B, "BDEV")).unwrap();
        hs.mark_changed(B);
        sync(&hs, &a, A, "ADEV");
        let e2 = send(&hs, &a, A, "ADEV", "after change");
        assert!(a.devices(B)["BDEV"].blocked.is_some());
        assert_eq!(a.devices(B)["BDEV"].curve25519, b2.identity().1);
        sync(&hs, &b2, B, "BDEV");
        assert_eq!(b2.decrypt_room(ROOM, &e2), Err(DecryptError::MissingSession), "no keys for a device that changed keys");
        // …and messages from it are refused.
        let r = send(&hs, &b2, B, "BDEV", "from the impostor");
        sync(&hs, &a, A, "ADEV");
        assert_eq!(a.decrypt_room(ROOM, &r), Err(DecryptError::MissingSession), "its room key was rejected");
        // Store: 0600, encrypted, reopened with the same identity; passphrase mode.
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("ADEV.e2ee");
        a.flush();
        for p in [path.clone(), path.with_extension("e2ee.key")] {
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(&a.identity().0) && !raw.contains("ADEV"), "nothing readable at rest");
        let id = a.identity();
        drop(a);
        let a2 = E2ee::open(A, &path, None, A, "ADEV").unwrap();
        assert_eq!(a2.identity(), id);
        assert_eq!(send(&hs, &a2, A, "ADEV", "resumed")["content"]["session_id"], e2["content"]["session_id"], "outbound session survives a restart");
        let pp = dir.join("pp.e2ee");
        let p1 = E2ee::open(A, &pp, Some("correct horse"), A, "PDEV").unwrap().identity();
        assert!(!pp.with_extension("e2ee.key").exists());
        assert_eq!(E2ee::open(A, &pp, Some("correct horse"), A, "PDEV").unwrap().identity(), p1);
        assert!(E2ee::open(A, &pp, Some("wrong"), A, "PDEV").err().unwrap().contains("wrong passphrase"));
        assert!(E2ee::open(A, &pp, None, A, "PDEV").err().unwrap().contains("passphrase"));
        assert_ne!(E2ee::open(A, &pp, Some("correct horse"), A, "OTHERDEV").unwrap().identity(), p1, "another device gets a new account");
    }

    /// Static vectors produced by vodozemac (matrix-sdk-crypto-wasm 18.9) with
    /// `tests/matrix_vectors_gen.mjs`: an Olm pre-key `m.room_key` to a device with
    /// fixed keys, three Megolm events and an `EncryptedFile`.
    #[test]
    fn decrypts_vodozemac_vectors() {
        let v: Value = serde_json::from_str(include_str!("../tests/fixtures/matrix_vodozemac_vectors.json")).unwrap();
        const ARK: &str = "@ark:hs.test";
        const ALICE: &str = "@alice:hs.test";
        let room = "!vec:hs.test";
        let hs = FakeHs::new(room, &[ARK, ALICE], json!({"algorithm": MEGOLM}));
        hs.handle(ALICE, "ALICEDEV", "POST", "/_matrix/client/v3/keys/upload", &json!({"device_keys": v["alice_device_keys"]})).unwrap();
        let e = E2ee::open(ARK, &temp_dir("e2ee").join("v.e2ee"), None, ARK, "ARKDEV").unwrap();
        {
            let mut st = e.st.lock().unwrap();
            st.account = Account::from_secrets([1; 32], [2; 32]);
            st.account.one_time = vec![olm::OneTimeKey { id: 1, key: olm::Curve::from_secret([3; 32]), published: true }];
            st.uploaded = true;
            assert_eq!((st.account.ed25519(), st.account.curve25519(), b64(&st.account.one_time[0].key.public)), (s(&v["ark_ed25519"]).into(), s(&v["ark_curve25519"]).into(), s(&v["otk"]).into()), "Ed25519/X25519 public keys match node's");
        }
        let call = hs.call_as(ARK, "ARKDEV");
        e.on_sync(&json!({"to_device": {"events": [{"type": "m.room.encrypted", "sender": ALICE, "content": v["to_device"]}]}}), &call);
        assert!(e.st.lock().unwrap().account.one_time.is_empty(), "one-time key consumed by the pre-key message");
        for (i, want) in ["first", "second", "third"].iter().enumerate() {
            let ev = json!({"type": "m.room.encrypted", "sender": ALICE, "event_id": format!("$v{i}"), "content": v["events"][i]});
            assert_eq!(body(e.decrypt_room(room, &ev)), *want);
        }
        let ct = unb64(s(&v["attachment"]["ciphertext"])).unwrap();
        assert_eq!(decrypt_attachment(&ct, &v["attachment"]["info"]).unwrap(), b"vodozemac attachment vector");
    }

    #[test]
    fn olm_payload_checks() {
        let hs = FakeHs::new(ROOM, &[A, B], json!({"algorithm": MEGOLM}));
        let dir = temp_dir("e2ee");
        let (a, b) = (dev(&hs, &dir, A, "ADEV"), dev(&hs, &dir, B, "BDEV"));
        let call = hs.call_as(A, "ADEV");
        // A to-device event whose server-side sender differs from the Olm payload's sender is dropped.
        a.encrypt_room(ROOM, &hs.encryption, "m.room.message", &json!({"body": "x"}), &call).unwrap();
        let mut v = hs.call_as(B, "BDEV")("GET", "/_matrix/client/v3/sync?since=x", Value::Null).unwrap();
        v["to_device"]["events"][0]["sender"] = json!(C);
        b.on_sync(&v, &hs.call_as(B, "BDEV"));
        assert!(b.st.lock().unwrap().inbound.is_empty());
        // Attachments: CTR + hash.
        let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7) as u8).collect();
        let (ct, file) = encrypt_attachment(&data);
        assert_ne!(ct, data);
        assert_eq!((file["v"].as_str(), file["key"]["alg"].as_str(), unb64(s(&file["iv"])).unwrap()[8..].to_vec()), (Some("v2"), Some("A256CTR"), vec![0u8; 8]));
        assert_eq!(decrypt_attachment(&ct, &file).unwrap(), data);
        let mut bad = ct.clone();
        bad[5] ^= 1;
        assert!(decrypt_attachment(&bad, &file).unwrap_err().message.contains("sha256"));
        // Matrix spec appendix: signing JSON example (canonical form ignores `unsigned`/`signatures`).
        assert_eq!(signable(&json!({"b": 1, "a": "é", "unsigned": {"x": 1}, "signatures": {}})), r#"{"a":"é","b":1}"#);
    }
}
