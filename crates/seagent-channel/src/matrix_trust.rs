//! Matrix cross-signing, secret storage, key backup and SAS verification on top
//! of [`crate::matrix_e2ee::E2ee`] (client-server spec §"Cross-signing",
//! §"Secret storage", §"Sharing", §"Server-side key backups", §"Key verification
//! framework").
//!
//! - Cross-signing: if the account has no master key, seagent creates master /
//!   self-signing / user-signing Ed25519 keys and uploads them
//!   (`keys/device_signing/upload`; the transport answers user-interactive auth
//!   with the configured password), then signs its own device. If the account
//!   already has keys, the private keys come from secret storage (configured
//!   recovery key or passphrase) or, after verifying with another of our
//!   devices, from that device over `m.secret.request`/`m.secret.send`.
//! - Secret storage (`m.secret_storage.v1.aes-hmac-sha2`): holds the
//!   cross-signing keys and the backup key. When seagent creates it (no default key
//!   on the account) and no `recovery_key` is configured, the new recovery key
//!   is written to a 0600 file next to the E2EE store (never logged).
//! - Key backup (`m.megolm_backup.v1.curve25519-aes-sha2`): used only when we
//!   hold the private key for the server's current version (so a swapped
//!   version can never receive our keys); every inbound session (ours included)
//!   is uploaded; a session missing for an event is restored from it.
//! - SAS: requests (to-device or in a room) from users in `verify_from` are
//!   answered and confirmed automatically; the emoji / numbers are logged and
//!   handed to the transport as notices for the owner to compare. Auto-confirm
//!   means the other side's human comparison is what protects against a MITM.
//!   A completed verification marks the device (and master key) verified, signs
//!   their master key with our user-signing key (or, for our own devices, the
//!   device with our self-signing key) and fetches missing secrets.

use crate::matrix_backup::{self as bk, BACKUP_ALGORITHM};
use crate::matrix_e2ee::{fatal, now_ms, s, signable, BackupKey, CrossKeys, E2ee, InboundRec, Out, Store, MEGOLM};
use crate::matrix_sas::{Flow, Keys, Msg, Phase, SAS};
use crate::olm::{self, b64, key32, Curve, GroupInbound};
use crate::{write_private, ChannelError, ChannelErrorKind as K};
use seagent_net::urlencode as enc;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

type Call<'a> = crate::matrix_e2ee::Call<'a>;

const FLOW_TIMEOUT: Duration = Duration::from_secs(600);
const SECRETS: [&str; 4] = ["m.cross_signing.master", "m.cross_signing.self_signing", "m.cross_signing.user_signing", "m.megolm_backup.v1"];

fn rand32() -> [u8; 32] {
    seagent_net::crypto::random_bytes(32).try_into().unwrap()
}

fn txn(p: &str) -> String {
    format!("seagent-{p}-{}", seagent_net::crypto::random_token(9))
}

fn ed_pub(seed: &[u8; 32]) -> String {
    b64(&olm::ed25519_public(seed))
}

/// Add a signature by the Ed25519 key `seed` (key id `ed25519:<public key>`).
pub(crate) fn sign_with(v: &mut Value, user: &str, seed: &[u8; 32]) {
    let sig = b64(olm::ed25519_pair(seed).sign(signable(v).as_bytes()).as_ref());
    v["signatures"][user][format!("ed25519:{}", ed_pub(seed))] = json!(sig);
}

fn cross_obj(user: &str, usage: &str, seed: &[u8; 32]) -> Value {
    let p = ed_pub(seed);
    json!({"user_id": user, "usage": [usage], "keys": { format!("ed25519:{p}"): p }})
}

impl E2ee {
    /// After the device keys are up: cross-signing, key backup, startup self-verification.
    pub fn setup(&self, call: Call) {
        if let Err(e) = self.setup_cross_signing(call) {
            eprintln!("matrix {}: cross-signing: {e}", self.label);
        }
        if let Err(e) = self.setup_backup(call) {
            eprintln!("matrix {}: key backup: {e}", self.label);
        }
        self.startup_verification(call);
    }

    /// Notices and room events for the transport to deliver.
    pub fn take_out(&self) -> Vec<Out> {
        std::mem::take(&mut self.mem.lock().unwrap().out)
    }

    fn notice(&self, m: String) {
        eprintln!("matrix {}: {m}", self.label);
        self.mem.lock().unwrap().out.push(Out::Notice(m));
    }

    // ───────────── secret storage ─────────────

    fn account_data(&self, st: &Store, name: &str, call: Call) -> Result<Option<Value>, ChannelError> {
        match call("GET", &format!("/_matrix/client/v3/user/{}/account_data/{}", enc(&st.user_id), enc(name)), Value::Null) {
            Ok(v) if v.as_object().is_some_and(|o| !o.is_empty()) => Ok(Some(v)),
            Ok(_) => Ok(None),
            Err(e) if e.kind == K::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn put_account_data(&self, st: &Store, name: &str, v: Value, call: Call) -> Result<(), ChannelError> {
        call("PUT", &format!("/_matrix/client/v3/user/{}/account_data/{}", enc(&st.user_id), enc(name)), v).map(|_| ())
    }

    /// The account's default secret-storage key, if we can open it (configured recovery
    /// key / passphrase, or one we created). `create`: make one when the account has none.
    pub(crate) fn ssss_key(&self, st: &mut Store, create: bool, call: Call) -> Result<Option<(String, [u8; 32])>, ChannelError> {
        let default = self.account_data(st, "m.secret_storage.default_key", call)?.map(|v| s(&v["key"]).to_string()).filter(|k| !k.is_empty());
        if let Some(id) = default {
            let desc = self.account_data(st, &format!("m.secret_storage.key.{id}"), call)?.unwrap_or_default();
            let mut cands = vec![];
            if let Some(rk) = &self.opts.recovery_key {
                match bk::decode_recovery_key(rk) {
                    Some(k) => cands.push(k),
                    None if desc["passphrase"]["algorithm"] == "m.pbkdf2" => {
                        cands.push(bk::passphrase_key(rk, s(&desc["passphrase"]["salt"]), desc["passphrase"]["iterations"].as_u64().unwrap_or(0) as u32));
                    }
                    None => {}
                }
            }
            cands.extend(st.ssss.as_ref().filter(|(k, _)| *k == id).map(|(_, k)| *k));
            if let Some(k) = cands.into_iter().find(|k| bk::ssss_check(k, &desc)) {
                st.ssss = Some((id.clone(), k));
                return Ok(Some((id, k)));
            }
            if self.opts.recovery_key.is_some() {
                eprintln!("matrix {}: recovery_key does not open the account's secret storage key {id}", self.label);
            }
            return Ok(None);
        }
        if !create {
            return Ok(None);
        }
        let given = self.opts.recovery_key.as_deref().and_then(bk::decode_recovery_key);
        let key = given.unwrap_or_else(rand32);
        let id = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(16));
        self.put_account_data(st, &format!("m.secret_storage.key.{id}"), bk::ssss_key_description(&key), call)?;
        self.put_account_data(st, "m.secret_storage.default_key", json!({"key": id}), call)?;
        st.ssss = Some((id.clone(), key));
        self.save(st)?;
        if given.is_none() {
            let f = self.path.with_extension("recovery-key");
            write_private(&f, format!("{}\n", bk::encode_recovery_key(&key)).as_bytes()).map_err(|e| fatal(format!("writing {}: {e}", f.display())))?;
            self.notice(format!("created secret storage for {}; its recovery key is in {} (keep it safe, then set it as recovery_key)", st.user_id, f.display()));
        }
        Ok(Some((id, key)))
    }

    fn ssss_get(&self, st: &Store, k: &(String, [u8; 32]), name: &str, call: Call) -> Option<Vec<u8>> {
        let v = self.account_data(st, name, call).ok()??;
        bk::ssss_decrypt(&k.1, name, &v["encrypted"][&k.0])
    }

    fn ssss_put(&self, st: &Store, k: &(String, [u8; 32]), name: &str, secret: &str, call: Call) -> Result<(), ChannelError> {
        self.put_account_data(st, name, json!({"encrypted": { k.0.clone(): bk::ssss_encrypt(&k.1, name, secret.as_bytes()) }}), call)
    }

    /// A 32-byte secret stored as unpadded base64 (cross-signing seeds, backup key).
    fn ssss_key32(&self, st: &Store, k: &(String, [u8; 32]), name: &str, call: Call) -> Option<[u8; 32]> {
        key32(std::str::from_utf8(&self.ssss_get(st, k, name, call)?).ok()?)
    }

    // ───────────── cross-signing ─────────────

    fn setup_cross_signing(&self, call: Call) -> Result<(), ChannelError> {
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        let me = st.user_id.clone();
        st.outdated.insert(me.clone());
        self.ensure_devices(st, std::slice::from_ref(&me), call)?;
        let server = st.identities.get(&me).cloned();
        let ours = st.cross.as_ref().and_then(|c| c.master).map(|m| ed_pub(&m));
        match server {
            Some(id) if ours.as_deref() == Some(id.master.as_str()) => {}
            Some(id) => {
                st.cross = None;
                if let Some(k) = self.ssss_key(st, false, call)? {
                    let get = |name: &str, want: Option<&String>| self.ssss_key32(st, &k, name, call).filter(|seed| want == Some(&ed_pub(seed)));
                    let keys = CrossKeys { master: get("m.cross_signing.master", Some(&id.master)), self_signing: get("m.cross_signing.self_signing", id.self_signing.as_ref()), user_signing: get("m.cross_signing.user_signing", id.user_signing.as_ref()) };
                    if keys.master.is_some() || keys.self_signing.is_some() {
                        st.cross = Some(keys);
                    }
                }
                if st.cross.is_none() {
                    eprintln!("matrix {}: {me} has cross-signing keys seagent does not hold: this device stays unverified until verified from another session or recovery_key is set", self.label);
                    return self.save(st);
                }
            }
            None if self.opts.cross_signing => self.bootstrap_cross_signing(st, call)?,
            None => return Ok(()),
        }
        if let Some(i) = st.identities.get_mut(&me) {
            if st.cross.as_ref().and_then(|c| c.master).is_some_and(|m| ed_pub(&m) == i.master) {
                i.verified = true;
                i.changed = false;
            }
        }
        let dev = st.device_id.clone();
        self.cross_sign_own(st, &dev, call)?;
        self.save(st)
    }

    fn bootstrap_cross_signing(&self, st: &mut Store, call: Call) -> Result<(), ChannelError> {
        let me = st.user_id.clone();
        let (m, ss, us) = (rand32(), rand32(), rand32());
        let mut ssk = cross_obj(&me, "self_signing", &ss);
        sign_with(&mut ssk, &me, &m);
        let mut usk = cross_obj(&me, "user_signing", &us);
        sign_with(&mut usk, &me, &m);
        call("POST", "/_matrix/client/v3/keys/device_signing/upload", json!({"master_key": cross_obj(&me, "master", &m), "self_signing_key": ssk, "user_signing_key": usk}))?;
        st.cross = Some(CrossKeys { master: Some(m), self_signing: Some(ss), user_signing: Some(us) });
        self.save(st)?;
        eprintln!("matrix {}: created cross-signing keys for {me} (master {})", self.label, ed_pub(&m));
        match self.ssss_key(st, true, call) {
            Ok(Some(k)) => {
                for (name, seed) in [("m.cross_signing.master", m), ("m.cross_signing.self_signing", ss), ("m.cross_signing.user_signing", us)] {
                    self.ssss_put(st, &k, name, &b64(&seed), call)?;
                }
            }
            Ok(None) => eprintln!("matrix {}: the account's secret storage cannot be opened (set recovery_key); cross-signing keys stay only in the local store", self.label),
            Err(e) => eprintln!("matrix {}: secret storage: {e}", self.label),
        }
        st.outdated.insert(me.clone());
        self.ensure_devices(st, &[me], call)
    }

    /// Sign one of our devices (this one included) with our self-signing key, and the
    /// master key with this device, if not done yet.
    fn cross_sign_own(&self, st: &mut Store, dev: &str, call: Call) -> Result<(), ChannelError> {
        let me = st.user_id.clone();
        let Some(ssk) = st.cross.as_ref().and_then(|c| c.self_signing) else { return Ok(()) };
        let Some(d) = st.devices.get(&me).and_then(|m| m.get(dev)).cloned() else { return Ok(()) };
        if d.cross_signed && st.identities.get(&me).is_some_and(|i| i.self_signing.as_deref() == Some(ed_pub(&ssk).as_str())) {
            return Ok(());
        }
        let mut keys = if dev == st.device_id { Self::device_keys(st) } else { d.keys.clone() };
        sign_with(&mut keys, &me, &ssk);
        let mut body = json!({ me.clone(): { dev: keys } });
        if dev == st.device_id {
            if let Some(i) = st.identities.get(&me).filter(|i| i.master_obj.is_object()) {
                let mut m = i.master_obj.clone();
                Self::sign(st, &mut m);
                body[&me][&i.master] = m;
            }
        }
        let r = call("POST", "/_matrix/client/v3/keys/signatures/upload", body)?;
        if r["failures"].as_object().is_some_and(|f| !f.is_empty()) {
            return Err(ChannelError::new(K::Protocol, format!("signature upload failed: {}", r["failures"])));
        }
        st.outdated.insert(me.clone());
        self.ensure_devices(st, &[me], call)
    }

    // ───────────── key backup ─────────────

    fn setup_backup(&self, call: Call) -> Result<(), ChannelError> {
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        let info = match call("GET", "/_matrix/client/v3/room_keys/version", Value::Null) {
            Ok(v) if v["version"].is_string() => Some(v),
            Ok(_) => None,
            Err(e) if e.kind == K::NotFound => None,
            Err(e) => return Err(e),
        };
        match info {
            Some(v) if v["algorithm"] == BACKUP_ALGORITHM => {
                let (version, public) = (s(&v["version"]).to_string(), s(&v["auth_data"]["public_key"]).to_string());
                let fits = |k: &[u8; 32]| b64(&Curve::from_secret(*k).public) == public;
                if st.backup.as_ref().is_some_and(|b| b.version == version && fits(&b.secret)) {
                    return Ok(());
                }
                let mut found = st.backup.as_ref().map(|b| b.secret).filter(fits);
                if found.is_none() {
                    if let Some(k) = self.ssss_key(st, false, call)? {
                        found = self.ssss_key32(st, &k, "m.megolm_backup.v1", call).filter(fits);
                    }
                }
                // A pre-secret-storage backup recovery key encodes the backup key itself.
                found = found.or_else(|| self.opts.recovery_key.as_deref().and_then(bk::decode_recovery_key).filter(fits));
                match found {
                    Some(secret) => {
                        st.backup = Some(BackupKey { version: version.clone(), secret });
                        st.inbound.values_mut().for_each(|r| r.backed_up = false);
                        eprintln!("matrix {}: using key backup version {version}", self.label);
                    }
                    None => {
                        st.backup = None;
                        eprintln!("matrix {}: the account has key backup version {version} but seagent does not hold its key (set recovery_key)", self.label);
                    }
                }
                self.save(st)
            }
            Some(v) => {
                eprintln!("matrix {}: unsupported key backup algorithm {}", self.label, v["algorithm"]);
                Ok(())
            }
            None if self.opts.key_backup => {
                let Some(k) = self.ssss_key(st, true, call)? else {
                    eprintln!("matrix {}: not creating a key backup: the account's secret storage cannot be opened (set recovery_key)", self.label);
                    return Ok(());
                };
                let secret = rand32();
                let mut auth = json!({"public_key": b64(&Curve::from_secret(secret).public)});
                Self::sign(st, &mut auth);
                if let Some(m) = st.cross.as_ref().and_then(|c| c.master) {
                    sign_with(&mut auth, &st.user_id, &m);
                }
                let r = call("POST", "/_matrix/client/v3/room_keys/version", json!({"algorithm": BACKUP_ALGORITHM, "auth_data": auth}))?;
                let version = r["version"].as_str().filter(|v| !v.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "room_keys/version: no version"))?.to_string();
                self.ssss_put(st, &k, "m.megolm_backup.v1", &b64(&secret), call)?;
                st.backup = Some(BackupKey { version: version.clone(), secret });
                st.inbound.values_mut().for_each(|r| r.backed_up = false);
                eprintln!("matrix {}: created key backup version {version}", self.label);
                self.save(st)
            }
            None => Ok(()),
        }
    }

    /// Upload sessions not yet in the backup (100 per request).
    pub(crate) fn backup_pending(&self, st: &mut Store, call: Call) {
        let Some(b) = st.backup.clone() else { return };
        let public = Curve::from_secret(b.secret).public;
        let ids: Vec<String> = st.inbound.iter().filter(|(_, r)| !r.backed_up && !r.sender.is_empty()).map(|(k, _)| k.clone()).take(100).collect();
        if ids.is_empty() {
            return;
        }
        let mut rooms = json!({});
        for id in &ids {
            let r = &st.inbound[id];
            let Some((room, sid)) = id.split_once('\n') else { continue };
            let plain = json!({"algorithm": MEGOLM, "sender_key": r.sender_key, "session_key": r.session.export(), "sender_claimed_keys": {"ed25519": r.claimed_ed25519}, "forwarding_curve25519_key_chain": r.chain});
            let verified = st.devices.get(&r.sender).is_some_and(|m| m.values().any(|d| d.curve25519 == r.sender_key && (d.verified || d.cross_signed)));
            rooms[room]["sessions"][sid] = json!({"first_message_index": r.session.first_index(), "forwarded_count": r.chain.len(), "is_verified": verified, "session_data": bk::backup_encrypt(&public, plain.to_string().as_bytes())});
        }
        match call("PUT", &format!("/_matrix/client/v3/room_keys/keys?version={}", enc(&b.version)), json!({"rooms": rooms})) {
            Ok(_) => {
                for id in &ids {
                    if let Some(r) = st.inbound.get_mut(id) {
                        r.backed_up = true;
                    }
                }
                if let Err(e) = self.save(st) {
                    eprintln!("matrix {}: {e}", self.label);
                }
            }
            Err(e) => {
                eprintln!("matrix {}: key backup upload: {e}", self.label);
                if e.message.contains("M_WRONG_ROOM_KEYS_VERSION") {
                    st.backup = None;
                }
            }
        }
    }

    /// Fetch one session from the backup; it must belong to a device of `sender`.
    pub(crate) fn restore_session(&self, st: &mut Store, room: &str, sid: &str, sender: &str, call: Call) -> bool {
        let Some(b) = st.backup.clone() else { return false };
        let Ok(v) = call("GET", &format!("/_matrix/client/v3/room_keys/keys/{}/{}?version={}", enc(room), enc(sid), enc(&b.version)), Value::Null) else { return false };
        match self.import_backed_up(st, room, sid, sender, &v, call) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("matrix {}: backed-up session {sid}: {e}", self.label);
                false
            }
        }
    }

    fn import_backed_up(&self, st: &mut Store, room: &str, sid: &str, sender: &str, data: &Value, call: Call) -> Result<(), String> {
        let secret = st.backup.as_ref().ok_or("no backup key")?.secret;
        let plain = bk::backup_decrypt(&secret, &data["session_data"]).ok_or("cannot decrypt it")?;
        let p: Value = serde_json::from_slice(&plain).map_err(|_| "not JSON")?;
        if p["algorithm"] != MEGOLM {
            return Err(format!("unsupported algorithm {}", p["algorithm"]));
        }
        let g = GroupInbound::from_session_key(s(&p["session_key"])).map_err(|e| e.to_string())?;
        if g.id() != sid {
            return Err("session id mismatch".into());
        }
        let sk = s(&p["sender_key"]);
        if self.device_by_curve(st, sender, sk, call).is_none() {
            return Err(format!("its sender_key is not a device of {sender}"));
        }
        let chain = p["forwarding_curve25519_key_chain"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let rec = InboundRec { session: g, sender: sender.into(), sender_key: sk.into(), seen: BTreeMap::new(), claimed_ed25519: s(&p["sender_claimed_keys"]["ed25519"]).into(), chain, backed_up: true };
        self.add_inbound(st, room, rec, call);
        Ok(())
    }

    // ───────────── secrets over to-device ─────────────

    fn request_secrets(&self, st: &Store, dev: &str, call: Call) {
        let have_backup = st.backup.is_some();
        let c = st.cross.clone();
        let missing: Vec<&str> = SECRETS
            .into_iter()
            .filter(|n| match *n {
                "m.cross_signing.master" => c.as_ref().is_none_or(|c| c.master.is_none()),
                "m.cross_signing.self_signing" => c.as_ref().is_none_or(|c| c.self_signing.is_none()),
                "m.cross_signing.user_signing" => c.as_ref().is_none_or(|c| c.user_signing.is_none()),
                _ => !have_backup,
            })
            .collect();
        for name in missing {
            let id = txn("sr");
            self.mem.lock().unwrap().secret_requests.insert(id.clone(), (name.to_string(), dev.to_string()));
            let c = json!({"name": name, "action": "request", "requesting_device_id": st.device_id, "request_id": id});
            if let Err(e) = call("PUT", &format!("/_matrix/client/v3/sendToDevice/m.secret.request/{}", enc(&txn("td"))), json!({"messages": { st.user_id.clone(): { dev: c } }})) {
                eprintln!("matrix {}: m.secret.request: {e}", self.label);
            }
        }
    }

    /// A secret we asked our verified device for.
    pub(crate) fn on_secret_send(&self, st: &mut Store, sender: &str, dev: &str, c: &Value, call: Call) -> Result<(), String> {
        let (name, asked) = self.mem.lock().unwrap().secret_requests.remove(s(&c["request_id"])).ok_or("m.secret.send we did not ask for")?;
        if sender != st.user_id || asked != dev || Self::own_verified(st, dev).is_none() {
            return Err("m.secret.send from a device we did not ask".into());
        }
        let secret = key32(s(&c["secret"])).ok_or("bad secret")?;
        let me = st.user_id.clone();
        let id = st.identities.get(&me).cloned().unwrap_or_default();
        let cross = st.cross.get_or_insert(CrossKeys { master: None, self_signing: None, user_signing: None });
        let ok = match name.as_str() {
            "m.cross_signing.master" if ed_pub(&secret) == id.master => {
                cross.master = Some(secret);
                true
            }
            "m.cross_signing.self_signing" if id.self_signing.as_deref() == Some(ed_pub(&secret).as_str()) => {
                cross.self_signing = Some(secret);
                true
            }
            "m.cross_signing.user_signing" if id.user_signing.as_deref() == Some(ed_pub(&secret).as_str()) => {
                cross.user_signing = Some(secret);
                true
            }
            "m.megolm_backup.v1" => {
                let v = call("GET", "/_matrix/client/v3/room_keys/version", Value::Null).map_err(|e| e.to_string())?;
                let fits = v["algorithm"] == BACKUP_ALGORITHM && s(&v["auth_data"]["public_key"]) == b64(&Curve::from_secret(secret).public);
                if fits {
                    st.backup = Some(BackupKey { version: s(&v["version"]).into(), secret });
                    st.inbound.values_mut().for_each(|r| r.backed_up = false);
                }
                fits
            }
            _ => false,
        };
        if st.cross.as_ref().is_some_and(|c| c.master.is_none() && c.self_signing.is_none() && c.user_signing.is_none()) {
            st.cross = None;
        }
        if !ok {
            return Err(format!("secret {name} does not match our published key"));
        }
        eprintln!("matrix {}: received {name} from our device {dev}", self.label);
        if name == "m.cross_signing.self_signing" {
            let ours = st.device_id.clone();
            self.cross_sign_own(st, &ours, call).map_err(|e| e.to_string())?;
        }
        self.save(st).map_err(|e| e.to_string())
    }

    /// Our verified device asks for a secret we hold.
    pub(crate) fn on_secret_request(&self, st: &mut Store, sender: &str, c: &Value, call: Call) -> Result<(), String> {
        let dev = s(&c["requesting_device_id"]).to_string();
        if sender != st.user_id || c["action"] != "request" || dev == st.device_id {
            return Ok(());
        }
        let cross = st.cross.clone();
        let secret = match s(&c["name"]) {
            "m.cross_signing.master" => cross.and_then(|c| c.master),
            "m.cross_signing.self_signing" => cross.and_then(|c| c.self_signing),
            "m.cross_signing.user_signing" => cross.and_then(|c| c.user_signing),
            "m.megolm_backup.v1" => st.backup.as_ref().map(|b| b.secret),
            _ => None,
        };
        let Some(secret) = secret else { return Ok(()) };
        if Self::own_verified(st, &dev).is_none() {
            let me = st.user_id.clone();
            st.outdated.insert(me.clone());
            self.ensure_devices(st, &[me], call).map_err(|e| e.to_string())?;
        }
        let d = Self::own_verified(st, &dev).ok_or_else(|| format!("secret request from our unverified device {dev}; ignored"))?;
        self.send_olm(st, &[(st.user_id.clone(), dev, d)], "m.secret.send", &json!({"request_id": c["request_id"], "secret": b64(&secret)}), call).map(|_| ())
    }

    // ───────────── verification ─────────────

    fn accepts(&self, st: &Store, user: &str) -> bool {
        self.opts.verify_from.iter().any(|v| v == "*" || v == user || (v == "self" && user == st.user_id))
    }

    fn our_keys(st: &Store) -> Keys {
        let master = st.identities.get(&st.user_id).filter(|i| i.verified && !i.changed).map(|i| i.master.clone());
        Keys { device_ed25519: st.account.ed25519(), master }
    }

    fn their_keys(st: &Store, user: &str, dev: &str) -> Keys {
        Keys { device_ed25519: st.devices.get(user).and_then(|m| m.get(dev)).map(|d| d.ed25519.clone()).unwrap_or_default(), master: st.identities.get(user).map(|i| i.master.clone()) }
    }

    fn send_flow(&self, f: &Flow, msgs: Vec<Msg>, call: Call) {
        for (typ, c) in msgs {
            match &f.room {
                Some(room) => self.mem.lock().unwrap().out.push(Out::Room { room: room.clone(), typ, content: c, flow_for: None }),
                None => {
                    let dev = f.their_device.clone().unwrap_or_else(|| "*".into());
                    if let Err(e) = call("PUT", &format!("/_matrix/client/v3/sendToDevice/{}/{}", enc(&typ), enc(&txn("td"))), json!({"messages": { f.them.clone(): { dev: c } }})) {
                        eprintln!("matrix {}: {typ} to {}: {e}", self.label, f.them);
                    }
                }
            }
        }
    }

    /// One `m.key.verification.*` event (to-device, or in `room`).
    pub(crate) fn on_verification(&self, st: &mut Store, sender: &str, typ: &str, c: &Value, room: Option<&str>, call: Call) -> Result<(), String> {
        let short = typ.trim_start_matches("m.key.verification.");
        let me = (st.user_id.clone(), st.device_id.clone());
        if sender == me.0 && (s(&c["from_device"]) == me.1 || room.is_some()) {
            return Ok(());
        }
        let fid = match room {
            Some(_) => s(&c["m.relates_to"]["event_id"]).to_string(),
            None => s(&c["transaction_id"]).to_string(),
        };
        if fid.is_empty() {
            return Err("verification event without a flow id".into());
        }
        let from_dev = s(&c["from_device"]).to_string();
        if !from_dev.is_empty() && !st.devices.get(sender).is_some_and(|m| m.contains_key(&from_dev)) {
            st.outdated.insert(sender.to_string());
            self.ensure_devices(st, &[sender.to_string()], call).map_err(|e| e.to_string())?;
        }
        let before = self.mem.lock().unwrap().flows.get(&fid).map(|f| f.phase);
        let exists = before.is_some();
        let mut f = if !exists && (short == "request" || (short == "start" && room.is_none())) {
            let mut f = Flow::new(&fid, room, (&me.0, &me.1), sender, Some(&from_dev), false);
            let stale = c["timestamp"].as_u64().is_some_and(|t| now_ms().abs_diff(t) > FLOW_TIMEOUT.as_millis() as u64);
            if stale {
                return Ok(());
            }
            let out = if !self.accepts(st, sender) {
                self.notice(format!("ignoring a verification request from {sender} {from_dev} (not in verify_from)"));
                f.cancel("m.user", "this bot does not accept verification requests from you")
            } else if short == "request" && !c["methods"].as_array().is_some_and(|a| a.iter().any(|m| m == SAS)) {
                f.cancel("m.unknown_method", "only m.sas.v1 is supported")
            } else {
                self.notice(format!("verification request from {sender} {from_dev}: accepting (emoji / decimal SAS)"));
                if short == "request" {
                    f.ready()
                } else {
                    f.on_start(c)
                }
            };
            self.send_flow(&f, out, call);
            f
        } else {
            let Some(mut f) = self.mem.lock().unwrap().flows.remove(&fid) else { return Ok(()) };
            if f.them != sender {
                self.mem.lock().unwrap().flows.insert(fid, f);
                return Err("verification event from a user not in this flow".into());
            }
            let out = match short {
                "ready" => {
                    let out = f.on_ready(c);
                    let others: Vec<String> = self.mem.lock().unwrap().flow_targets.remove(&fid).unwrap_or_default().into_iter().filter(|d| *d != from_dev).collect();
                    if !others.is_empty() {
                        let cancel = json!({"transaction_id": fid, "code": "m.accepted", "reason": "verification accepted by another device"});
                        let msgs: serde_json::Map<String, Value> = others.into_iter().map(|d| (d, cancel.clone())).collect();
                        let _ = call("PUT", &format!("/_matrix/client/v3/sendToDevice/m.key.verification.cancel/{}", enc(&txn("td"))), json!({"messages": { sender: msgs }}));
                    }
                    out
                }
                "start" => f.on_start(c),
                "accept" => f.on_accept(c),
                "key" => f.on_key(c),
                "mac" => {
                    // Fresh keys: they may have set up cross-signing since we last looked.
                    st.outdated.insert(sender.to_string());
                    if let Err(e) = self.ensure_devices(st, &[sender.to_string()], call) {
                        eprintln!("matrix {}: keys/query {sender}: {e}", self.label);
                    }
                    let theirs = Self::their_keys(st, sender, f.their_device.as_deref().unwrap_or(""));
                    f.on_mac(c, &theirs)
                }
                "cancel" => {
                    f.phase = Phase::Cancelled;
                    self.notice(format!("verification with {sender} cancelled by them: {} {}", s(&c["code"]), s(&c["reason"])));
                    vec![]
                }
                _ => vec![],
            };
            self.send_flow(&f, out, call);
            f
        };
        if f.phase == Phase::Keys {
            if let Some(codes) = f.describe() {
                self.notice(format!("verification with {} {}: compare these on their screen: {codes}", f.them, f.their_device.clone().unwrap_or_default()));
            }
            let out = f.confirm(&Self::our_keys(st));
            self.send_flow(&f, out, call);
        }
        if before != Some(f.phase) {
            match f.phase {
                Phase::Cancelled if short != "cancel" => self.notice(format!("verification with {} failed", f.them)),
                Phase::Done => self.apply_verified(st, &f, call),
                _ => {}
            }
        }
        self.mem.lock().unwrap().flows.insert(fid, f);
        Ok(())
    }

    fn apply_verified(&self, st: &mut Store, f: &Flow, call: Call) {
        let Some(v) = &f.verified else { return };
        let (them, dev, me) = (f.them.clone(), f.their_device.clone().unwrap_or_default(), st.user_id.clone());
        if v.device {
            if let Some(d) = st.devices.get_mut(&them).and_then(|m| m.get_mut(&dev)) {
                d.verified = true;
                d.blocked = None;
            }
        }
        if let Some(m) = &v.master {
            if let Some(i) = st.identities.get_mut(&them).filter(|i| i.master == *m) {
                i.verified = true;
                i.changed = false;
            }
        }
        self.notice(format!("verified {them} {dev}{}", if v.master.is_some() { " and their cross-signing identity" } else { "" }));
        let r = if them == me {
            self.request_secrets(st, &dev, call);
            self.cross_sign_own(st, &dev, call)
        } else if let (Some(usk), Some(m)) = (st.cross.as_ref().and_then(|c| c.user_signing), &v.master) {
            let mut obj = st.identities.get(&them).map(|i| i.master_obj.clone()).unwrap_or_default();
            if obj.is_object() {
                obj.as_object_mut().unwrap().remove("signatures");
                sign_with(&mut obj, &me, &usk);
                call("POST", "/_matrix/client/v3/keys/signatures/upload", json!({ them.clone(): { m.clone(): obj } })).map(|_| ())
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };
        if let Err(e) = r {
            eprintln!("matrix {}: after verifying {them} {dev}: {e}", self.label);
        }
        if let Err(e) = self.save(st) {
            eprintln!("matrix {}: {e}", self.label);
        }
    }

    pub(crate) fn expire_flows(&self) {
        self.mem.lock().unwrap().flows.retain(|_, f| f.created.elapsed() < FLOW_TIMEOUT && !(f.finished() && f.created.elapsed() > Duration::from_secs(60)));
    }

    /// Start a to-device verification with `user`'s devices (all but this one).
    pub fn request_verification(&self, user: &str, call: Call) -> Result<String, ChannelError> {
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        st.outdated.insert(user.to_string());
        self.ensure_devices(st, &[user.to_string()], call)?;
        let devs: Vec<String> = st.devices.get(user).into_iter().flatten().filter(|(d, dev)| !(user == st.user_id && **d == st.device_id) && dev.blocked.is_none()).map(|(d, _)| d.clone()).collect();
        if devs.is_empty() {
            return Err(ChannelError::new(K::NotFound, format!("{user} has no other devices to verify with")));
        }
        let id = txn("v");
        let f = Flow::new(&id, None, (&st.user_id, &st.device_id), user, None, true);
        let c = f.request(now_ms());
        let msgs: serde_json::Map<String, Value> = devs.iter().map(|d| (d.clone(), c.clone())).collect();
        call("PUT", &format!("/_matrix/client/v3/sendToDevice/m.key.verification.request/{}", enc(&txn("td"))), json!({"messages": { user: msgs }}))?;
        let mut mem = self.mem.lock().unwrap();
        mem.flows.insert(id.clone(), f);
        mem.flow_targets.insert(id.clone(), devs);
        Ok(id)
    }

    /// In-room verification request content for `user` (send it as `m.room.message`,
    /// then report the event id with [`E2ee::room_request_sent`]).
    pub fn room_request(&self, user: &str) -> Value {
        let st = self.st.lock().unwrap();
        Flow::new("", Some("!"), (&st.user_id, &st.device_id), user, None, true).request(now_ms())
    }

    pub fn room_request_sent(&self, room: &str, event_id: &str, user: &str) {
        let st = self.st.lock().unwrap();
        let f = Flow::new(event_id, Some(room), (&st.user_id, &st.device_id), user, None, true);
        self.mem.lock().unwrap().flows.insert(event_id.to_string(), f);
    }

    /// A (decrypted) room event that belongs to an in-room verification: handled here.
    pub fn on_room_event(&self, room: &str, ev: &Value, call: Call) -> bool {
        let (typ, c) = (s(&ev["type"]), &ev["content"]);
        let mut st = self.st.lock().unwrap();
        let r = if typ == "m.room.message" && c["msgtype"] == "m.key.verification.request" {
            let old = ev["origin_server_ts"].as_u64().is_some_and(|t| now_ms().saturating_sub(t) > FLOW_TIMEOUT.as_millis() as u64);
            if c["to"] != st.user_id.as_str() || old {
                return true;
            }
            let mut c = c.clone();
            c["m.relates_to"] = json!({"rel_type": "m.reference", "event_id": ev["event_id"]});
            self.on_verification(&mut st, s(&ev["sender"]), "m.key.verification.request", &c, Some(room), call)
        } else if typ.starts_with("m.key.verification.") {
            self.on_verification(&mut st, s(&ev["sender"]), typ, c, Some(room), call)
        } else {
            return false;
        };
        if let Err(e) = r {
            eprintln!("matrix {}: verification in {room}: {e}", self.label);
        }
        true
    }

    /// OpenClaw's `startupVerification: if-unverified`: ask our other devices to verify
    /// this one when it is not cross-signed (at most once per cooldown).
    fn startup_verification(&self, call: Call) {
        if !self.opts.startup_verification {
            return;
        }
        let me = {
            let mut st = self.st.lock().unwrap();
            let now = now_ms();
            let me = st.user_id.clone();
            let signed = st.devices.get(&me).and_then(|m| m.get(&st.device_id)).is_some_and(|d| d.cross_signed);
            let others = st.devices.get(&me).is_some_and(|m| m.keys().any(|d| *d != st.device_id));
            if signed || !others || !st.identities.contains_key(&me) || now.saturating_sub(st.startup_verify_ms) < self.opts.startup_verification_cooldown_ms {
                return;
            }
            st.startup_verify_ms = now;
            let _ = self.save(&st);
            me
        };
        match self.request_verification(&me, call) {
            Ok(_) => self.notice(format!("this device ({me}) is not cross-signed: asked our other sessions to verify it")),
            Err(e) => eprintln!("matrix {}: startup verification: {e}", self.label),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix_e2ee::fake_hs::FakeHs;
    use crate::matrix_e2ee::{DecryptError, Device, Opts, Trust};
    use crate::testutil::temp_dir;
    use std::path::Path;

    const ROOM: &str = "!r:hs.test";
    const A: &str = "@a:hs.test";
    const B: &str = "@b:hs.test";
    const C: &str = "@c:hs.test";

    fn dev(hs: &FakeHs, dir: &Path, user: &'static str, d: &'static str, opts: Opts) -> E2ee {
        let mut e = E2ee::open(user, &dir.join(format!("{d}.e2ee")), None, user, d).unwrap();
        e.opts = opts;
        let call = hs.call_as(user, d);
        e.ensure_uploaded(&call).unwrap();
        e.setup(&call);
        e
    }

    fn sync(hs: &FakeHs, e: &E2ee, user: &'static str, d: &'static str) -> Value {
        let call = hs.call_as(user, d);
        let v = call("GET", "/_matrix/client/v3/sync?since=x", Value::Null).unwrap();
        e.on_sync(&v, &call);
        v
    }

    /// Sync every device until nothing moves (to-device ping-pong).
    fn settle(hs: &FakeHs, devs: &[(&E2ee, &'static str, &'static str)]) {
        for _ in 0..8 {
            for (e, u, d) in devs {
                sync(hs, e, u, d);
            }
        }
    }

    fn send(hs: &FakeHs, e: &E2ee, user: &'static str, d: &'static str, body: &str) -> Value {
        let call = hs.call_as(user, d);
        let c = e.encrypt_room(ROOM, &hs.encryption, "m.room.message", &json!({"msgtype": "m.text", "body": body}), &call).unwrap();
        let id = call("PUT", &format!("/_matrix/client/v3/rooms/{}/send/m.room.encrypted/t", enc(ROOM)), c.clone()).unwrap();
        json!({"type": "m.room.encrypted", "sender": user, "event_id": id["event_id"], "content": c})
    }

    fn device(e: &E2ee, user: &str, d: &str) -> Device {
        e.st.lock().unwrap().devices[user][d].clone()
    }

    fn query(e: &E2ee, hs: &FakeHs, me: &'static str, d: &'static str, user: &str) {
        let mut st = e.st.lock().unwrap();
        st.outdated.insert(user.into());
        e.ensure_devices(&mut st, &[user.into()], &hs.call_as(me, d)).unwrap();
    }

    fn notices(e: &E2ee) -> Vec<String> {
        e.take_out().into_iter().filter_map(|o| if let Out::Notice(n) = o { Some(n) } else { None }).collect()
    }

    fn quiet() -> Opts {
        Opts { startup_verification: false, ..Opts::default() }
    }

    #[test]
    fn cross_signing_secret_storage_and_backup_bootstrap() {
        let hs = FakeHs::new(ROOM, &[A, B], json!({"algorithm": MEGOLM}));
        let dir = temp_dir("mxt");
        let a = dev(&hs, &dir, A, "ADEV", quiet());
        // Recovery key written 0600, never in the notices' text.
        let rk_file = dir.join("ADEV.recovery-key");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&rk_file).unwrap().permissions().mode() & 0o777, 0o600);
        let rk = std::fs::read_to_string(&rk_file).unwrap().trim().to_string();
        let n = notices(&a);
        assert!(n.iter().any(|n| n.contains("recovery-key")) && !n.iter().any(|n| n.contains(&rk)), "{n:?}");
        // Secret storage holds the three cross-signing keys and the backup key.
        let key = bk::decode_recovery_key(&rk).unwrap();
        let kid = s(&hs.account_data(A, "m.secret_storage.default_key").unwrap()["key"]).to_string();
        assert!(bk::ssss_check(&key, &hs.account_data(A, &format!("m.secret_storage.key.{kid}")).unwrap()));
        for name in SECRETS {
            let v = hs.account_data(A, name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(bk::ssss_decrypt(&key, name, &v["encrypted"][&kid]).map(|p| p.len()), Some(43), "{name}");
        }
        // B sees A's device cross-signed by A's self-signing key; master pinned.
        let b = dev(&hs, &dir, B, "BDEV", quiet());
        query(&b, &hs, B, "BDEV", A);
        assert!(device(&b, A, "ADEV").cross_signed);
        let ida = b.st.lock().unwrap().identities[A].clone();
        assert!(!ida.verified && ida.self_signing.is_some() && ida.user_signing.is_none(), "only our own user-signing key is visible");
        assert!(a.st.lock().unwrap().identities[A].verified, "our own identity: we hold the master key");
        // A second device of A, given the recovery key: takes the keys from secret storage,
        // cross-signs itself and joins the existing backup.
        let a2 = dev(&hs, &dir, A, "ADEV2", Opts { recovery_key: Some(rk.clone()), ..quiet() });
        assert!(a2.st.lock().unwrap().cross.as_ref().is_some_and(|c| c.master.is_some() && c.self_signing.is_some() && c.user_signing.is_some()));
        assert_eq!(a2.st.lock().unwrap().backup.as_ref().map(|b| b.version.clone()), Some("1".into()), "no second backup version");
        query(&b, &hs, B, "BDEV", A);
        assert!(device(&b, A, "ADEV2").cross_signed);
        // A third device without the key: stays unsigned; cross_signed trust refuses it.
        let a3 = dev(&hs, &dir, A, "ADEV3", Opts { key_backup: false, ..quiet() });
        assert!(a3.st.lock().unwrap().cross.is_none());
        let mut strict = E2ee::open(B, &dir.join("strict.e2ee"), None, B, "BDEV9").unwrap();
        strict.opts.trust = Trust::CrossSigned;
        query(&strict, &hs, B, "BDEV9", A);
        let st = strict.st.lock().unwrap();
        assert_eq!(strict.distrust(&st, A, "ADEV3", &st.devices[A]["ADEV3"]).as_deref(), Some("not cross-signed by its owner"));
        assert_eq!(strict.distrust(&st, A, "ADEV", &st.devices[A]["ADEV"]), None);
        drop(st);
        // Wrong recovery key: nothing loaded.
        let bad = dev(&hs, &dir, A, "ADEV4", Opts { recovery_key: Some(bk::encode_recovery_key(&[7; 32])), key_backup: false, ..quiet() });
        assert!(bad.st.lock().unwrap().cross.is_none());
        // A master key change: pinned identity flags it under cross_signed trust.
        hs.handle(A, "ADEV", "POST", "/_matrix/client/v3/keys/device_signing/upload", &json!({"master_key": cross_obj(A, "master", &[9; 32]), "self_signing_key": {}, "user_signing_key": {}})).unwrap();
        query(&strict, &hs, B, "BDEV9", A);
        let st = strict.st.lock().unwrap();
        assert!(st.identities[A].changed);
        assert!(strict.distrust(&st, A, "ADEV", &st.devices[A]["ADEV"]).unwrap().contains("identity changed"));
    }

    #[test]
    fn self_verification_secrets_backup_and_key_requests() {
        let hs = FakeHs::new(ROOM, &[A, B], json!({"algorithm": MEGOLM}));
        let dir = temp_dir("mxt");
        let a = dev(&hs, &dir, A, "ADEV", quiet());
        let b = dev(&hs, &dir, B, "BDEV", quiet());
        let e1 = send(&hs, &b, B, "BDEV", "before the new device");
        sync(&hs, &a, A, "ADEV");
        assert_eq!(s(&a.decrypt_room(ROOM, &e1).unwrap()["content"]["body"]), "before the new device");
        let sid = s(&e1["content"]["session_id"]).to_string();
        assert!(hs.backup(A, ROOM, &sid).is_some(), "a backed up the session it received");
        // A new device without any secrets: startup verification asks ADEV.
        let a3 = dev(&hs, &dir, A, "ADEV3", Opts { key_backup: false, ..Opts::default() });
        assert!(notices(&a3).iter().any(|n| n.contains("asked our other sessions")));
        assert_eq!(a3.decrypt_room(ROOM, &e1), Err(DecryptError::MissingSession));
        assert!(!a3.on_missing(ROOM, &e1, &hs.call_as(A, "ADEV3")), "no backup key, so a key request goes out");
        sync(&hs, &a, A, "ADEV");
        assert!(!a.st.lock().unwrap().sessions.contains_key(&a3.identity().1), "unverified own device: request ignored, no Olm traffic");
        settle(&hs, &[(&a, A, "ADEV"), (&a3, A, "ADEV3")]);
        let (na, n3) = (notices(&a), notices(&a3));
        let codes = |n: &[String]| n.iter().find(|n| n.contains("compare")).map(|n| n.split(": ").last().unwrap().to_string());
        assert!(codes(&na).is_some() && codes(&na) == codes(&n3), "{na:?} {n3:?}");
        assert!(na.iter().any(|n| n.contains("verified @a:hs.test ADEV3")) && n3.iter().any(|n| n.contains("verified @a:hs.test ADEV and their cross-signing identity")), "{na:?} {n3:?}");
        assert!(device(&a, A, "ADEV3").verified && device(&a3, A, "ADEV").verified);
        // ADEV cross-signed ADEV3 and sent it the secrets it asked for.
        let st3 = a3.st.lock().unwrap();
        assert!(st3.cross.as_ref().is_some_and(|c| c.master.is_some() && c.self_signing.is_some() && c.user_signing.is_some()), "secrets arrived");
        assert_eq!(st3.backup.as_ref().map(|b| b.version.as_str()), Some("1"));
        drop(st3);
        query(&b, &hs, B, "BDEV", A);
        assert!(device(&b, A, "ADEV3").cross_signed);
        // The earlier key request is still outstanding; a new one now gets answered by ADEV.
        a3.st.lock().unwrap().requested.clear();
        a3.st.lock().unwrap().backup = None;
        assert!(!a3.on_missing(ROOM, &e1, &hs.call_as(A, "ADEV3")));
        settle(&hs, &[(&a, A, "ADEV"), (&a3, A, "ADEV3")]);
        assert_eq!(s(&a3.decrypt_room(ROOM, &e1).unwrap()["content"]["body"]), "before the new device", "m.forwarded_room_key accepted");
        assert!(a3.st.lock().unwrap().requested.is_empty());
        assert!(hs.sent_todev.lock().unwrap().iter().any(|(t, from, _, c)| t == "m.room_key_request" && from == A && c["action"] == "request_cancellation"));
        // Restore from the backup on another fresh device holding the recovery key.
        let rk = std::fs::read_to_string(dir.join("ADEV.recovery-key")).unwrap();
        let a4 = dev(&hs, &dir, A, "ADEV4", Opts { recovery_key: Some(rk), ..quiet() });
        assert!(a4.on_missing(ROOM, &e1, &hs.call_as(A, "ADEV4")), "restored from backup");
        assert_eq!(s(&a4.decrypt_room(ROOM, &e1).unwrap()["content"]["body"]), "before the new device");
        // Unrequested forwarded keys and forged attributions are refused.
        let mut forged = e1.clone();
        forged["sender"] = json!(A);
        assert!(matches!(a4.decrypt_room(ROOM, &forged), Err(DecryptError::Rejected(_))));
    }

    #[test]
    fn in_room_sas_between_users_and_user_signing() {
        let hs = FakeHs::new(ROOM, &[A, B, C], json!({"algorithm": MEGOLM}));
        let dir = temp_dir("mxt");
        let a = dev(&hs, &dir, A, "ADEV", Opts { verify_from: vec!["*".into()], ..quiet() });
        let b = dev(&hs, &dir, B, "BDEV", quiet());
        let c = dev(&hs, &dir, C, "CDEV", quiet());
        let devs = [(&a, A, "ADEV"), (&b, B, "BDEV"), (&c, C, "CDEV")];
        let mut seen = 0;
        let pump = |seen: &mut usize| {
            for _ in 0..10 {
                for (e, u, d) in devs {
                    for o in e.take_out() {
                        if let Out::Room { room, typ, content, .. } = o {
                            hs.handle(u, d, "PUT", &format!("/_matrix/client/v3/rooms/{}/send/{}/t", enc(&room), enc(&typ)), &content).unwrap();
                        }
                    }
                }
                let tl = hs.timeline();
                for ev in &tl[*seen..] {
                    for (e, u, d) in devs {
                        let mut ev = ev.clone();
                        ev["origin_server_ts"] = json!(now_ms());
                        e.on_room_event(ROOM, &ev, &hs.call_as(u, d));
                    }
                }
                *seen = tl.len();
            }
        };
        // B asks A in the room; A accepts anyone (verify_from = *).
        let req = b.room_request(A);
        assert_eq!((req["msgtype"].as_str(), req["to"].as_str()), (Some("m.key.verification.request"), Some(A)));
        let id = hs.handle(B, "BDEV", "PUT", &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/t", enc(ROOM)), &req).unwrap();
        b.room_request_sent(ROOM, s(&id["event_id"]), A);
        pump(&mut seen);
        let types: Vec<String> = hs.timeline().iter().map(|e| s(&e["type"]).to_string()).collect();
        assert_eq!(types[1..], ["m.key.verification.ready", "m.key.verification.start", "m.key.verification.accept", "m.key.verification.key", "m.key.verification.key", "m.key.verification.mac", "m.key.verification.mac", "m.key.verification.done", "m.key.verification.done"].map(String::from), "{types:?}");
        assert!(hs.timeline()[1..].iter().all(|e| e["content"]["m.relates_to"]["event_id"] == id["event_id"]));
        assert!(device(&a, B, "BDEV").verified && device(&b, A, "ADEV").verified);
        assert!(a.st.lock().unwrap().identities[B].verified && b.st.lock().unwrap().identities[A].verified, "master keys MAC'd and verified");
        // A signed B's master key with its user-signing key: visible to A after a re-query.
        let usk = a.st.lock().unwrap().identities[A].user_signing.clone().unwrap();
        let q = hs.call_as(A, "ADEV")("POST", "/_matrix/client/v3/keys/query", json!({"device_keys": {B: []}})).unwrap();
        assert!(crate::matrix_e2ee::verify_json(&q["master_keys"][B], A, &format!("ed25519:{usk}"), &usk));
        let fresh = E2ee::open(A, &dir.join("fresh.e2ee"), None, A, "ADEV").unwrap();
        fresh.st.lock().unwrap().identities = a.st.lock().unwrap().identities.clone();
        query(&fresh, &hs, A, "ADEV", B);
        assert!(fresh.st.lock().unwrap().identities[B].verified, "user-signing signature makes B's identity verified");
        // C does not accept requests from B (verify_from = self): cancelled with m.user.
        let req = b.room_request(C);
        let id = hs.handle(B, "BDEV", "PUT", &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/t", enc(ROOM)), &req).unwrap();
        b.room_request_sent(ROOM, s(&id["event_id"]), C);
        pump(&mut seen);
        let last = hs.timeline().last().unwrap().clone();
        assert_eq!((last["type"].as_str(), last["content"]["code"].as_str(), last["sender"].as_str()), (Some("m.key.verification.cancel"), Some("m.user"), Some(C)));
    }

    #[test]
    fn unwedging_invites_and_visibility() {
        let hs = FakeHs::new(ROOM, &[A, B], json!({"algorithm": MEGOLM}));
        let dir = temp_dir("mxt");
        let o = Opts { cross_signing: false, key_backup: false, ..quiet() };
        let a = dev(&hs, &dir, A, "ADEV", o.clone());
        let b = dev(&hs, &dir, B, "BDEV", o.clone());
        let c = dev(&hs, &dir, C, "CDEV", o.clone());
        send(&hs, &a, A, "ADEV", "one");
        sync(&hs, &b, B, "BDEV");
        send(&hs, &b, B, "BDEV", "reply");
        sync(&hs, &a, A, "ADEV");
        // b loses its Olm sessions; a's next room key (a normal Olm message) cannot be read.
        b.st.lock().unwrap().sessions.clear();
        a.st.lock().unwrap().outbound.clear();
        let dummies = || hs.sent_todev.lock().unwrap().iter().filter(|(t, from, to, _)| t == "m.room.encrypted" && from == B && to == A).count();
        let before = dummies();
        let e2 = send(&hs, &a, A, "ADEV", "two");
        sync(&hs, &b, B, "BDEV");
        assert_eq!(dummies(), before + 1, "m.dummy on a fresh session");
        let a_curve = a.identity().1;
        assert!(b.st.lock().unwrap().dummy_sent.contains_key(&a_curve));
        sync(&hs, &a, A, "ADEV");
        assert_eq!(a.st.lock().unwrap().sessions[&b.identity().1].len(), 2, "a opened the new inbound session from the m.dummy");
        assert_eq!(b.decrypt_room(ROOM, &e2), Err(DecryptError::MissingSession));
        // Again within the hour: no second m.dummy.
        b.st.lock().unwrap().sessions.clear();
        a.st.lock().unwrap().outbound.clear();
        send(&hs, &a, A, "ADEV", "three");
        sync(&hs, &b, B, "BDEV");
        assert_eq!(dummies(), before + 1, "rate limited to one per hour per device");
        // An invited member gets the room key while history is shared…
        *hs.invited.lock().unwrap() = vec![C.into()];
        a.st.lock().unwrap().outbound.clear();
        a.mem.lock().unwrap().members.clear();
        let e4 = send(&hs, &a, A, "ADEV", "for the invitee");
        sync(&hs, &c, C, "CDEV");
        assert_eq!(s(&c.decrypt_room(ROOM, &e4).unwrap()["content"]["body"]), "for the invitee");
        // …but not once history_visibility is `joined`.
        let vis = json!({"rooms": {"join": {ROOM: {"timeline": {"events": [{"type": "m.room.history_visibility", "state_key": "", "content": {"history_visibility": "joined"}}]}}}}});
        a.on_sync(&vis, &hs.call_as(A, "ADEV"));
        a.st.lock().unwrap().outbound.clear();
        let e5 = send(&hs, &a, A, "ADEV", "members only");
        sync(&hs, &c, C, "CDEV");
        assert_eq!(c.decrypt_room(ROOM, &e5), Err(DecryptError::MissingSession));
    }
}
