//! Discord Audio & Video End-to-End Encryption (DAVE) protocol v1, written
//! from the protocol whitepaper (github.com/discord/dave-protocol, v1.1.4)
//! and checked against libdave's session/encryptor/decryptor logic.
//!
//! * Group key exchange: one MLS group per call (`mls`, cipher suite 2), group
//!   id = the voice channel id (big endian), the voice gateway as the single
//!   external sender. Handles ops 21–31: key package (26), external sender
//!   (25), proposals append/revoke (27, Add/Remove from the external sender
//!   only, adds checked against clients_connect), our commit + welcome (28),
//!   announced commits (29, ours is recognised byte-for-byte and its cached
//!   state adopted), welcomes (30, group id / external sender / roster
//!   checked), prepare/execute transitions and epochs (21/22/24), invalid
//!   commit recovery (31 then a fresh key package), sole-member reset.
//! * Media keys: `MLS-Exporter("Discord Secure Frames v0", user id LE, 16)` per
//!   sender per epoch, run through the MLS hash ratchet; the generation is the
//!   top byte of the 32-bit nonce. Previous epochs stay usable for 10 s.
//! * Frame transform: AES-128-GCM with the tag truncated to 8 bytes, ULEB128
//!   nonce and unencrypted ranges, supplemental size byte and 0xFAFA marker.
//!   Opus frames are fully encrypted; the SFU's 0xF8FFFE silence passes.
//!   ring only verifies full 16-byte tags, so decryption derives the GCM
//!   keystream by sealing zeros and re-seals the plaintext to recompute the
//!   tag (two passes, but no hand-written AES).
//! * Identity: the MLS signature key can persist across calls (libdave's
//!   generic key store: a JWK file written 0600); pairwise verification
//!   fingerprints follow libdave `PairwiseFingerprint` (MIT, Discord): key
//!   fingerprints `u16 version ‖ key ‖ u64 user id` (big endian), sorted,
//!   concatenated, scrypt(N=16384, r=8, p=2, 64) with libdave's fixed salt, shown
//!   as 45 digits in groups of 5.

use crate::mls::{self, Cached, Credential, ExternalSender, Group, KeyPackage, Proposal, Sender, Signer, R, W};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "scrypt.rs"]
pub mod scrypt;

pub const MAX_PROTOCOL_VERSION: u16 = 1;
pub const EXPORT_LABEL: &str = "Discord Secure Frames v0";
pub const OPUS_SILENCE: [u8; 3] = [0xF8, 0xFF, 0xFE];
const MARKER: [u8; 2] = [0xFA, 0xFA];
const TAG: usize = 8;
const MIN_SUPPLEMENTAL: usize = TAG + 1 + 2;
const KEEP_OLD: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- frame codec

pub fn uleb_write(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push(0x80 | (v & 0x7f) as u8);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn uleb_read(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let byte = *b.get(*i)?;
        *i += 1;
        if shift > 63 {
            return None;
        }
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
}

/// A parsed protocol frame (the "protocol frame check" passed).
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The interleaved media frame (ciphertext with unencrypted ranges in place).
    pub body: &'a [u8],
    pub tag: &'a [u8],
    pub nonce: u32,
    pub ranges: Vec<(usize, usize)>,
}

pub fn parse_frame(f: &[u8]) -> Option<Frame<'_>> {
    let n = f.len();
    if n < MIN_SUPPLEMENTAL || f[n - 2..] != MARKER {
        return None;
    }
    let supp = f[n - 3] as usize;
    if supp < MIN_SUPPLEMENTAL || supp > n {
        return None;
    }
    let start = n - supp;
    let meta = &f[start + TAG..n - 3];
    let mut i = 0;
    let nonce = u32::try_from(uleb_read(meta, &mut i)?).ok()?;
    let body = &f[..start];
    let mut ranges = Vec::new();
    let mut end = 0;
    while i < meta.len() {
        let (off, len) = (uleb_read(meta, &mut i)? as usize, uleb_read(meta, &mut i)? as usize);
        if off < end || off.checked_add(len)? > body.len() {
            return None;
        }
        end = off + len;
        ranges.push((off, len));
    }
    Some(Frame { body, tag: &f[start..start + TAG], nonce, ranges })
}

fn full_nonce(n: u32) -> [u8; 12] {
    let mut v = [0u8; 12];
    v[8..].copy_from_slice(&n.to_le_bytes());
    v
}

/// Encrypt a fully-encrypted (Opus) frame.
pub fn encrypt_frame(key: &[u8; 16], nonce: u32, frame: &[u8]) -> Vec<u8> {
    let sealed = mls::seal(key, &full_nonce(nonce), &[], frame).expect("AES-128-GCM seal");
    let (ct, tag) = sealed.split_at(frame.len());
    let mut out = ct.to_vec();
    out.extend_from_slice(&tag[..TAG]);
    let mut meta = Vec::new();
    uleb_write(nonce as u64, &mut meta);
    out.extend_from_slice(&meta);
    out.push((MIN_SUPPLEMENTAL + meta.len()) as u8);
    out.extend_from_slice(&MARKER);
    out
}

/// Decrypt a parsed protocol frame with one key; None when the truncated tag does not verify.
pub fn decrypt_frame(key: &[u8; 16], f: &Frame) -> Option<Vec<u8>> {
    let inside = |x: usize| f.ranges.iter().any(|(o, l)| x >= *o && x < o + l);
    let (mut aad, mut ct) = (Vec::new(), Vec::new());
    for (x, b) in f.body.iter().enumerate() {
        if inside(x) { aad.push(*b) } else { ct.push(*b) }
    }
    let nonce = full_nonce(f.nonce);
    // GCM: ciphertext = plaintext ⊕ keystream, and the keystream is what zeros encrypt to.
    let ks = mls::seal(key, &nonce, &[], &vec![0u8; ct.len()]).ok()?;
    let pt: Vec<u8> = ct.iter().zip(&ks).map(|(c, k)| c ^ k).collect();
    let check = mls::seal(key, &nonce, &aad, &pt).ok()?;
    if !seagent_net::crypto::ct_eq(&check[pt.len()..pt.len() + TAG], f.tag) {
        return None;
    }
    let (mut out, mut p, mut a) = (Vec::with_capacity(f.body.len()), pt.into_iter(), aad.into_iter());
    for x in 0..f.body.len() {
        out.push(if inside(x) { a.next()? } else { p.next()? });
    }
    Some(out)
}

// ---------------------------------------------------------------- key ratchet

/// The MLS hash ratchet (RFC 9420 §9.1) over a DAVE sender base secret; keys of
/// earlier generations stay cached until erased.
pub struct KeyRatchet {
    next_secret: Vec<u8>,
    next_gen: u32,
    keys: BTreeMap<u32, [u8; 16]>,
}

impl KeyRatchet {
    pub fn new(base: Vec<u8>) -> KeyRatchet {
        KeyRatchet { next_secret: base, next_gen: 0, keys: BTreeMap::new() }
    }

    pub fn get(&mut self, generation: u32) -> Option<[u8; 16]> {
        if let Some(k) = self.keys.get(&generation) {
            return Some(*k);
        }
        // Erased generations stay erased; refuse absurd jumps (libdave: 250).
        if generation < self.next_gen || generation > self.next_gen + 250 {
            return None;
        }
        while self.next_gen <= generation {
            let key: [u8; 16] = mls::derive_tree_secret(&self.next_secret, "key", self.next_gen, 16).try_into().unwrap();
            self.keys.insert(self.next_gen, key);
            self.next_secret = mls::derive_tree_secret(&self.next_secret, "secret", self.next_gen, mls::NH);
            self.next_gen += 1;
        }
        while self.keys.len() > 4 {
            let first = *self.keys.keys().next().unwrap();
            self.keys.remove(&first);
        }
        self.keys.get(&generation).copied()
    }
}

struct RecvKeys {
    ratchet: KeyRatchet,
    expires: Option<Instant>,
    /// Highest nonce seen and a 64-entry replay window below it.
    top: Option<u32>,
    window: u64,
}

impl RecvKeys {
    fn fresh(&self, n: u32) -> bool {
        match self.top {
            None => true,
            Some(t) if n > t => true,
            Some(t) => t - n < 64 && self.window & (1 << (t - n)) == 0,
        }
    }
    fn mark(&mut self, n: u32) {
        match self.top {
            Some(t) if n <= t => self.window |= 1 << (t - n),
            Some(t) => {
                let shift = n - t;
                self.window = if shift >= 64 { 0 } else { self.window << shift } | 1;
                self.top = Some(n);
            }
            None => {
                self.top = Some(n);
                self.window = 1;
            }
        }
    }
}

// ---------------------------------------------------------------- session

/// Something to send on the voice gateway.
#[derive(Debug, Clone, PartialEq)]
pub enum Out {
    Json(Value),
    /// Opcode byte + payload.
    Binary(Vec<u8>),
}

/// A roster change after a commit or welcome.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Roster {
    pub joined: Vec<u64>,
    pub left: Vec<u64>,
}

struct Pending {
    leaf: mls::LeafNode,
    leaf_priv: [u8; 32],
    kp: Option<(KeyPackage, [u8; 32])>,
    group: Option<Group>,
}

/// One DAVE session (one voice connection).
pub struct Dave {
    pub user_id: u64,
    pub channel_id: u64,
    /// Version announced by the gateway; 0 = transport encryption only.
    pub protocol_version: u16,
    /// Version our sender currently uses (changes on execute transition).
    pub send_version: u16,
    signer: Arc<Signer>,
    external: Option<ExternalSender>,
    pending: Option<Pending>,
    group: Option<Group>,
    proposals: Vec<Cached>,
    outbound: Option<(Vec<u8>, Group)>,
    pub recognized: HashSet<u64>,
    transitions: HashMap<u16, u16>,
    send: Option<(KeyRatchet, u32)>,
    recv: HashMap<u64, Vec<RecvKeys>>,
    /// Plaintext from other senders is accepted until (downgrades/upgrades in flight).
    passthrough_until: Option<Instant>,
    roster: HashSet<u64>,
    pub errors: Vec<String>,
}

fn user_of(c: &Credential) -> Option<u64> {
    (c.kind == 1 && c.body.len() == 8).then(|| u64::from_be_bytes(c.body[..].try_into().unwrap()))
}

impl Dave {
    pub fn new(user_id: u64, channel_id: u64) -> Dave {
        Dave::with_signer(user_id, channel_id, Arc::new(Signer::generate()))
    }

    /// With a (persistent) signature key.
    pub fn with_signer(user_id: u64, channel_id: u64, signer: Arc<Signer>) -> Dave {
        Dave {
            user_id,
            channel_id,
            protocol_version: 0,
            send_version: 0,
            signer,
            external: None,
            pending: None,
            group: None,
            proposals: vec![],
            outbound: None,
            recognized: HashSet::from([user_id]),
            transitions: HashMap::new(),
            send: None,
            recv: HashMap::new(),
            passthrough_until: None,
            roster: HashSet::new(),
            errors: vec![],
        }
    }

    pub fn group(&self) -> Option<&Group> {
        self.group.as_ref()
    }

    pub fn active(&self) -> bool {
        self.send_version > 0 && self.send.is_some()
    }

    fn group_id(&self) -> Vec<u8> {
        self.channel_id.to_be_bytes().to_vec()
    }

    /// Fresh leaf + key package; a pending one-member group once the external sender is known.
    fn reinit(&mut self) -> Vec<Out> {
        self.group = None;
        self.proposals.clear();
        self.outbound = None;
        self.roster.clear();
        let (leaf, leaf_priv) = mls::new_leaf(&self.user_id.to_be_bytes(), &self.signer);
        self.pending = Some(Pending { leaf, leaf_priv, kp: None, group: None });
        self.create_pending_group();
        self.key_package()
    }

    fn create_pending_group(&mut self) {
        let (Some(es), Some(p)) = (self.external.clone(), self.pending.as_mut()) else { return };
        if p.group.is_none() {
            p.group = Some(Group::create(&self.channel_id.to_be_bytes(), p.leaf.clone(), p.leaf_priv, self.signer.clone(), vec![ExternalSender::extension(&[es])]));
        }
    }

    /// Op 26: a new key package (never reused).
    fn key_package(&mut self) -> Vec<Out> {
        let Some(p) = self.pending.as_mut() else { return vec![] };
        let (init_priv, init_pub) = mls::generate_key_pair();
        let kp = KeyPackage::new(init_pub, p.leaf.clone(), &self.signer);
        let mut b = vec![26u8];
        b.extend_from_slice(&kp.message());
        p.kp = Some((kp, init_priv));
        vec![Out::Binary(b)]
    }

    /// Op 4 select_protocol_ack's `dave_protocol_version`.
    pub fn on_session_description(&mut self, version: u16) -> Vec<Out> {
        self.protocol_version = version;
        self.send_version = version;
        if version > 0 {
            self.reinit()
        } else {
            vec![]
        }
    }

    pub fn on_clients_connect(&mut self, ids: &[u64]) {
        self.recognized.extend(ids);
    }

    pub fn on_client_disconnect(&mut self, id: u64) {
        if id != self.user_id {
            self.recognized.remove(&id);
        }
    }

    /// Op 21.
    pub fn on_prepare_transition(&mut self, tid: u16, version: u16) -> Vec<Out> {
        self.transitions.insert(tid, version);
        if version == 0 {
            self.passthrough_until = Some(Instant::now() + Duration::from_secs(120));
        }
        if tid == 0 {
            self.on_execute_transition(0);
            vec![]
        } else {
            vec![Out::Json(json!({"op": 23, "d": {"transition_id": tid}}))]
        }
    }

    /// Op 22: senders switch to the prepared version / epoch.
    pub fn on_execute_transition(&mut self, tid: u16) {
        let Some(version) = self.transitions.remove(&tid) else { return };
        let was = self.send_version;
        self.send_version = version;
        self.protocol_version = version;
        if version == 0 {
            self.send = None;
            return;
        }
        if was == 0 {
            // Upgrade: senders catch up within a few seconds.
            self.passthrough_until = Some(Instant::now() + KEEP_OLD);
        }
        self.install_send_ratchet();
    }

    fn install_send_ratchet(&mut self) {
        if let Some(g) = &self.group {
            self.send = Some((KeyRatchet::new(g.export(EXPORT_LABEL, &self.user_id.to_le_bytes(), 16)), 0));
        }
    }

    /// Op 24: epoch 1 means the group is (re)created.
    pub fn on_prepare_epoch(&mut self, epoch: u64, version: u16) -> Vec<Out> {
        if epoch == 1 {
            self.protocol_version = version;
            return self.reinit();
        }
        vec![]
    }

    /// Op 25 payload.
    pub fn on_external_sender(&mut self, payload: &[u8]) -> Result<(), String> {
        let mut r = R::new(payload);
        let es = ExternalSender::dec(&mut r)?;
        r.end()?;
        self.external = Some(es);
        self.create_pending_group();
        Ok(())
    }

    fn base(&self) -> Option<&Group> {
        self.group.as_ref().or_else(|| self.pending.as_ref().and_then(|p| p.group.as_ref()))
    }

    /// Op 27 payload: append or revoke proposals, then commit what is queued (op 28).
    pub fn on_proposals(&mut self, payload: &[u8]) -> Result<Vec<Out>, String> {
        let Some(base) = self.base().cloned() else { return Ok(vec![]) };
        let mut r = R::new(payload);
        match r.u8()? {
            0 => {
                for m in mls::PublicMessage::split(r.vec()?)? {
                    let c = base.proposal(&m)?;
                    if c.sender != Sender::External(0) {
                        return Err("proposal not from the voice gateway".into());
                    }
                    match &c.proposal {
                        Proposal::Add(kp) => {
                            let uid = user_of(&kp.leaf.cred).ok_or("add proposal without a user id credential")?;
                            if !self.recognized.contains(&uid) {
                                return Err(format!("add proposal for unexpected user {uid}"));
                            }
                        }
                        Proposal::Remove(_) => {}
                        _ => return Err("only add/remove proposals are allowed".into()),
                    }
                    self.proposals.push(c);
                }
            }
            1 => {
                for rf in r.list(|r| Ok(r.vec()?.to_vec()))? {
                    let before = self.proposals.len();
                    self.proposals.retain(|c| c.reference != rf);
                    if self.proposals.len() == before {
                        return Err("revoke of an unknown proposal".into());
                    }
                }
            }
            t => return Err(format!("bad proposals operation {t}")),
        }
        r.end()?;
        if self.proposals.is_empty() {
            self.outbound = None;
            return Ok(vec![]);
        }
        let out = base.commit(&self.proposals, false)?;
        let mut b = vec![28u8];
        b.extend_from_slice(&out.commit);
        if let Some(w) = &out.welcome {
            b.extend_from_slice(w);
        }
        self.outbound = Some((out.commit, out.next));
        Ok(vec![Out::Binary(b)])
    }

    fn adopt(&mut self, g: Group, tid: u16) -> Result<(Roster, Vec<Out>), String> {
        let mut users = HashSet::new();
        for (_, l) in g.members() {
            let u = user_of(&l.cred).ok_or("member without a user id credential")?;
            if !users.insert(u) {
                return Err(format!("duplicate user {u} in the group"));
            }
        }
        let roster = Roster { joined: users.difference(&self.roster).copied().collect(), left: self.roster.difference(&users).copied().collect() };
        // Receivers prepare the new epoch's keys now and keep the old ones briefly.
        let now = Instant::now();
        for v in self.recv.values_mut() {
            for k in v.iter_mut() {
                k.expires.get_or_insert(now + KEEP_OLD);
            }
        }
        for u in &users {
            let ratchet = KeyRatchet::new(g.export(EXPORT_LABEL, &u.to_le_bytes(), 16));
            self.recv.entry(*u).or_default().insert(0, RecvKeys { ratchet, expires: None, top: None, window: 0 });
        }
        self.roster = users;
        self.group = Some(g);
        self.pending = None;
        self.proposals.clear();
        self.outbound = None;
        let version = self.protocol_version.max(1);
        let out = self.on_prepare_transition(tid, version);
        Ok((roster, out))
    }

    fn invalid(&mut self, tid: u16, e: String) -> Vec<Out> {
        self.errors.push(e);
        let mut out = vec![Out::Json(json!({"op": 31, "d": {"transition_id": tid}}))];
        out.extend(self.reinit());
        out
    }

    /// Op 29 payload: transition id + commit MLSMessage.
    pub fn on_announce_commit(&mut self, payload: &[u8]) -> (Option<Roster>, Vec<Out>) {
        if payload.len() < 2 {
            return (None, vec![]);
        }
        let tid = u16::from_be_bytes([payload[0], payload[1]]);
        let commit = &payload[2..];
        let next = match &self.outbound {
            Some((c, g)) if c == commit => Ok(g.clone()),
            _ => match &self.group {
                Some(g) => g.process_commit(commit, &self.proposals, &mls::no_psks),
                // An in-flight commit while we have no group: nothing to do.
                None => return (None, vec![]),
            },
        };
        match next.and_then(|g| self.adopt(g, tid)) {
            Ok((r, out)) => (Some(r), out),
            Err(e) => (None, self.invalid(tid, e)),
        }
    }

    /// Op 30 payload: transition id + Welcome.
    pub fn on_welcome(&mut self, payload: &[u8]) -> (Option<Roster>, Vec<Out>) {
        if payload.len() < 2 || self.group.is_some() {
            return (None, vec![]);
        }
        let tid = u16::from_be_bytes([payload[0], payload[1]]);
        let joined = (|| {
            let p = self.pending.as_ref().ok_or("welcome without a pending key package")?;
            let (kp, init) = p.kp.as_ref().ok_or("welcome without a key package")?;
            let es = self.external.as_ref().ok_or("welcome before the external sender")?;
            let g = Group::join(&payload[2..], kp, init, p.leaf_priv, self.signer.clone(), None, &mls::no_psks)?;
            if g.group_id != self.group_id() {
                return Err("welcome for another group".to_string());
            }
            if ExternalSender::from_extensions(&g.exts)? != [es.clone()] {
                return Err("welcome lists an unexpected external sender".into());
            }
            for (_, l) in g.members() {
                if !user_of(&l.cred).is_some_and(|u| self.recognized.contains(&u)) {
                    return Err("welcome lists an unrecognized user".into());
                }
            }
            Ok(g)
        })();
        match joined.and_then(|g| self.adopt(g, tid)) {
            Ok((r, out)) => (Some(r), out),
            Err(e) => (None, self.invalid(tid, e)),
        }
    }

    /// Our outgoing Opus frame → protocol frame (or unchanged in passthrough).
    pub fn encrypt(&mut self, frame: &[u8]) -> Vec<u8> {
        if self.send_version == 0 {
            return frame.to_vec();
        }
        let Some((ratchet, nonce)) = self.send.as_mut() else { return frame.to_vec() };
        *nonce = nonce.wrapping_add(1);
        match ratchet.get(*nonce >> 24) {
            Some(k) => encrypt_frame(&k, *nonce, frame),
            None => frame.to_vec(),
        }
    }

    /// A received frame from `user` → Opus, or None to drop it.
    pub fn decrypt(&mut self, user: u64, frame: &[u8]) -> Option<Vec<u8>> {
        if frame == OPUS_SILENCE {
            return Some(frame.to_vec());
        }
        let now = Instant::now();
        let Some(f) = parse_frame(frame) else {
            let pass = self.protocol_version == 0 || self.send_version == 0 || self.passthrough_until.is_some_and(|t| now < t);
            return pass.then(|| frame.to_vec());
        };
        let keys = self.recv.get_mut(&user)?;
        keys.retain(|k| k.expires.is_none_or(|t| now < t));
        for k in keys.iter_mut() {
            if !k.fresh(f.nonce) {
                continue;
            }
            if let Some(key) = k.ratchet.get(f.nonce >> 24) {
                if let Some(pt) = decrypt_frame(&key, &f) {
                    k.mark(f.nonce);
                    return Some(pt);
                }
            }
        }
        None
    }

    /// The epoch authenticator as Discord displays it (30 digits in groups of 5).
    pub fn verification_code(&self) -> Option<String> {
        let a = self.group.as_ref()?.epoch_authenticator();
        Some(displayable_code(a, 30, 5))
    }

    /// Our signature public key (what other members see in our leaf).
    pub fn signature_key(&self) -> Vec<u8> {
        self.signer.public()
    }

    /// Pairwise verification code with `user` (both sides display the same 45 digits).
    pub fn pairwise_code(&self, user: u64) -> Option<String> {
        let g = self.group.as_ref()?;
        let theirs = g.members().find(|(_, l)| user_of(&l.cred) == Some(user)).map(|(_, l)| l.sig_key.clone())?;
        Some(displayable_code(&pairwise_fingerprint(0, &self.signer.public(), self.user_id, &theirs, user), 45, 5))
    }
}

const FINGERPRINT_SALT: [u8; 16] = [0x24, 0xca, 0xb1, 0x7a, 0x7a, 0xf8, 0xec, 0x2b, 0x82, 0xb4, 0x12, 0xb9, 0x2d, 0xab, 0x19, 0x2e];

/// libdave `GenerateKeyFingerprint`: `u16 version ‖ key ‖ u64 user` (big endian).
pub fn key_fingerprint(version: u16, key: &[u8], user: u64) -> Vec<u8> {
    let mut v = version.to_be_bytes().to_vec();
    v.extend_from_slice(key);
    v.extend_from_slice(&user.to_be_bytes());
    v
}

/// libdave `GeneratePairwiseFingerprint` (64 bytes).
pub fn pairwise_fingerprint(version: u16, key_a: &[u8], user_a: u64, key_b: &[u8], user_b: u64) -> Vec<u8> {
    let mut f = [key_fingerprint(version, key_a, user_a), key_fingerprint(version, key_b, user_b)];
    f.sort();
    scrypt::scrypt(&f.concat(), &FINGERPRINT_SALT, 16384, 8, 2, 64)
}

/// libdave `GenerateDisplayableCode`: `len` digits, each group of `group` bytes
/// read big endian mod 10^group.
pub fn displayable_code(data: &[u8], len: usize, group: usize) -> String {
    let m = 10u64.pow(group as u32);
    (0..len / group).map(|i| format!("{:0w$}", data[i * group..i * group + group].iter().fold(0u64, |acc, b| acc << 8 | *b as u64) % m, w = group)).collect::<Vec<_>>().join(" ")
}

/// The persistent signature key: a P-256 JWK (`kty`, `crv`, `d`, `x`, `y`), created 0600 on first use.
pub fn load_or_create_signer(path: &std::path::Path) -> Result<Signer, String> {
    use seagent_net::crypto::{b64url, b64url_decode};
    if let Ok(raw) = std::fs::read_to_string(path) {
        let v: Value = serde_json::from_str(&raw).map_err(|e| format!("{}: bad JWK ({e})", path.display()))?;
        let d = v["d"].as_str().and_then(b64url_decode).filter(|d| d.len() == 32).ok_or_else(|| format!("{}: JWK without a P-256 `d`", path.display()))?;
        return Signer::from_scalar(&d).map_err(|e| format!("{}: {e}", path.display()));
    }
    let d = loop {
        let d = seagent_net::crypto::random_bytes(32);
        if crate::p256::valid_scalar(&d) {
            break d;
        }
    };
    let pk = crate::p256::public_key(&d).ok_or("P-256 key generation failed")?;
    let jwk = json!({"kty": "EC", "crv": "P-256", "d": b64url(&d), "x": b64url(&pk[1..33]), "y": b64url(&pk[33..])});
    write_private(path, jwk.to_string().as_bytes()).map_err(|e| format!("saving {}: {e}", path.display()))?;
    Signer::from_scalar(&d).map_err(|e| e.to_string())
}

fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    #[cfg(unix)]
    let mut f = o.open(&tmp)?;
    #[cfg(not(unix))]
    let mut f = crate::open_private_tmp(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// External sender package (op 25 payload) — what the voice gateway sends; used by tests and the doctor.
pub fn external_sender_payload(es: &ExternalSender) -> Vec<u8> {
    let mut w = W::default();
    es.enc(&mut w);
    w.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls::PublicMessage;

    /// libdave js/__tests__ KeyFingerprint, PairwiseFingerprint and DisplayableCode vectors.
    #[test]
    fn libdave_fingerprint_vectors() {
        let k = key_fingerprint(0, &[0; 33], 1234);
        assert_eq!(k.iter().map(|b| b.to_string()).collect::<String>(), "000000000000000000000000000000000000000004210");
        let k = key_fingerprint(0, &[0; 65], 12345678);
        assert_eq!(k.iter().map(|b| b.to_string()).collect::<String>(), "0000000000000000000000000000000000000000000000000000000000000000000000001889778");
        let want: [u8; 64] = [133, 129, 241, 44, 36, 135, 79, 195, 27, 28, 151, 69, 124, 197, 189, 41, 192, 7, 16, 45, 79, 247, 138, 58, 126, 161, 178, 136, 12, 109, 96, 164, 169, 92, 2, 232, 136, 174, 74, 156, 173, 144, 191, 184, 34, 45, 242, 136, 41, 133, 14, 158, 119, 79, 204, 48, 6, 220, 121, 6, 242, 11, 164, 60];
        assert_eq!(pairwise_fingerprint(0, &[0; 33], 1234, &[0; 65], 5678), want);
        assert_eq!(pairwise_fingerprint(0, &[0; 65], 5678, &[0; 33], 1234), want, "order-independent");
        let want: [u8; 64] = [141, 169, 194, 143, 22, 72, 22, 245, 13, 140, 66, 228, 159, 195, 101, 106, 119, 240, 69, 191, 178, 227, 194, 126, 162, 255, 222, 148, 138, 5, 33, 215, 240, 167, 234, 245, 149, 182, 46, 20, 4, 83, 191, 31, 165, 74, 253, 165, 199, 16, 29, 71, 193, 205, 169, 154, 255, 154, 34, 30, 94, 171, 247, 43];
        assert_eq!(pairwise_fingerprint(0, &[0, 100], 1, &[0, 20], 2), want, "sorted by fingerprint bytes");
        assert_eq!(displayable_code(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee], 5, 5), "05870");
        let long = seagent_net::crypto::hex_decode("aabbccddeebbccddeeffccddeeffaaddeeffaabbeeffaabbccffaabbccdd").unwrap();
        assert_eq!(displayable_code(&long, 30, 5).replace(' ', ""), "058708105556138052119572494877");
    }

    #[test]
    fn persistent_signature_key_is_0600_and_reloaded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::testutil::temp_dir("davekey");
        let path = dir.join("dave").join("dc.key");
        let a = load_or_create_signer(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let jwk: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!((jwk["kty"].as_str(), jwk["crv"].as_str()), (Some("EC"), Some("P-256")));
        let b = load_or_create_signer(&path).unwrap();
        assert_eq!(a.public(), b.public());
        let d = Dave::with_signer(1, 2, Arc::new(b));
        assert_eq!(d.signature_key(), a.public());
        std::fs::write(&path, "{}").unwrap();
        assert!(load_or_create_signer(&path).unwrap_err().contains("JWK"));
    }

    #[test]
    fn uleb128_and_frame_format() {
        for (v, enc) in [(0u64, vec![0u8]), (127, vec![0x7f]), (128, vec![0x80, 1]), (624485, vec![0xe5, 0x8e, 0x26]), (u32::MAX as u64, vec![0xff, 0xff, 0xff, 0xff, 0x0f])] {
            let mut b = vec![];
            uleb_write(v, &mut b);
            assert_eq!(b, enc);
            let mut i = 0;
            assert_eq!(uleb_read(&b, &mut i), Some(v));
        }
        let key = [7u8; 16];
        let opus = b"\x78\x01\x02opus payload".to_vec();
        let f = encrypt_frame(&key, 0x0100_0005, &opus);
        // body ‖ 8-byte tag ‖ ULEB nonce (4 bytes) ‖ size (8+4+1+2) ‖ FA FA
        assert_eq!(f.len(), opus.len() + 8 + 4 + 1 + 2);
        assert_eq!((f[f.len() - 3], &f[f.len() - 2..]), (15, &[0xfa, 0xfa][..]));
        let p = parse_frame(&f).unwrap();
        assert_eq!((p.nonce, p.ranges.len(), p.body.len()), (0x0100_0005, 0, opus.len()));
        assert_eq!(decrypt_frame(&key, &p).unwrap(), opus);
        // The truncated tag is checked: flip a ciphertext bit or use another key.
        let mut bad = f.clone();
        bad[0] ^= 1;
        assert!(decrypt_frame(&key, &parse_frame(&bad).unwrap()).is_none());
        assert!(decrypt_frame(&[8u8; 16], &p).is_none());
        // Ciphertext matches plain AES-128-GCM with nonce = 0^8 ‖ LE32(n) and the tag cut to 8 bytes.
        let mut nonce = [0u8; 12];
        nonce[8..].copy_from_slice(&0x0100_0005u32.to_le_bytes());
        let full = mls::seal(&key, &nonce, &[], &opus).unwrap();
        assert_eq!(&f[..opus.len() + 8], &full[..opus.len() + 8]);
        // Unencrypted ranges are authenticated and kept in place.
        let frame = b"HDRpayload!".to_vec();
        let sealed = mls::seal(&key, &full_nonce(9), b"HDR", b"payload!").unwrap();
        let mut g = b"HDR".to_vec();
        g.extend_from_slice(&sealed[..8]);
        g.extend_from_slice(&sealed[8..16]);
        g.extend_from_slice(&[9, 0, 3]);
        g.push(8 + 3 + 1 + 2);
        g.extend_from_slice(&MARKER);
        let p = parse_frame(&g).unwrap();
        assert_eq!(p.ranges, [(0, 3)]);
        assert_eq!(decrypt_frame(&key, &p).unwrap(), frame);
        // Non-protocol frames fail the check.
        for junk in [&b"\xfc\xff\xfe"[..], &b"short"[..], &[0u8; 20][..], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 200, 0xfa, 0xfa][..]] {
            assert!(parse_frame(junk).is_none());
        }
    }

    #[test]
    fn key_ratchet_is_the_mls_hash_ratchet() {
        let base = vec![3u8; 16];
        let mut r = KeyRatchet::new(base.clone());
        let k0 = r.get(0).unwrap();
        assert_eq!(k0.to_vec(), mls::derive_tree_secret(&base, "key", 0, 16));
        let s1 = mls::derive_tree_secret(&base, "secret", 0, 32);
        assert_eq!(r.get(1).unwrap().to_vec(), mls::derive_tree_secret(&s1, "key", 1, 16));
        assert_eq!(r.get(0), Some(k0), "cached");
        r.get(10).unwrap();
        assert!(r.get(0).is_none(), "erased after moving on");
        assert!(r.get(400).is_none(), "too far ahead");
    }

    /// The voice gateway's side: external sender and proposals.
    struct Gateway {
        signer: Signer,
        es: ExternalSender,
    }

    impl Gateway {
        fn new() -> Gateway {
            let signer = Signer::generate();
            let es = ExternalSender { sig_key: signer.public(), cred: Credential::basic(b"voice gateway") };
            Gateway { signer, es }
        }
        fn proposal(&self, g: &Group, p: Proposal) -> Vec<u8> {
            mls::external_proposal(&self.signer, 0, &g.group_id, g.epoch, p)
        }
        fn append(&self, msgs: &[Vec<u8>]) -> Vec<u8> {
            let mut w = W::default();
            w.u8(0).vec(&msgs.concat());
            w.0
        }
    }

    fn binary(out: &[Out], op: u8) -> Option<Vec<u8>> {
        out.iter().find_map(|o| match o {
            Out::Binary(b) if b[0] == op => Some(b[1..].to_vec()),
            _ => None,
        })
    }

    fn kp_of(out: &[Out]) -> KeyPackage {
        mls::parse_key_package(&binary(out, 26).unwrap()).unwrap()
    }

    /// Two clients create a group through a scripted gateway, exchange media, then a third joins
    /// and the first leaves; every key change goes through ops 26–30 and transitions.
    #[test]
    fn group_lifecycle_and_media() {
        let gw = Gateway::new();
        let es_payload = external_sender_payload(&gw.es);
        let (mut a, mut b) = (Dave::new(111, 999), Dave::new(222, 999));
        let kpa = kp_of(&a.on_session_description(1));
        let kpb = kp_of(&b.on_session_description(1));
        for d in [&mut a, &mut b] {
            d.on_external_sender(&es_payload).unwrap();
            d.on_clients_connect(&[111, 222, 333]);
        }
        // Initial group creation: each pending member is proposed to the other's local group.
        let pa = a.base().unwrap().clone();
        let pb = b.base().unwrap().clone();
        let out_a = a.on_proposals(&gw.append(&[gw.proposal(&pa, Proposal::Add(kpb.clone()))])).unwrap();
        let out_b = b.on_proposals(&gw.append(&[gw.proposal(&pb, Proposal::Add(kpa.clone()))])).unwrap();
        assert!(binary(&out_b, 28).is_some(), "B commits too, but A's commit wins");
        let cw = binary(&out_a, 28).unwrap();
        let commit = {
            let mut r = R::new(&cw);
            let start = r.i;
            PublicMessage::read(&mut r).unwrap();
            r.since(start).to_vec()
        };
        let welcome = cw[commit.len()..].to_vec();
        let mut ann = 7u16.to_be_bytes().to_vec();
        ann.extend_from_slice(&commit);
        let (roster, out) = a.on_announce_commit(&ann);
        assert_eq!(out, vec![Out::Json(json!({"op": 23, "d": {"transition_id": 7}}))]);
        assert_eq!(roster.unwrap().joined.len(), 2);
        let mut wel = 7u16.to_be_bytes().to_vec();
        wel.extend_from_slice(&welcome);
        let (roster, out) = b.on_welcome(&wel);
        assert!(roster.is_some(), "{:?}", b.errors);
        assert!(matches!(&out[..], [Out::Json(v)] if v["op"] == 23));
        assert_eq!(a.verification_code(), b.verification_code());
        assert_eq!(a.verification_code().unwrap().len(), 35);
        // Pairwise fingerprint: same 45 digits on both sides, different per pair.
        let code = a.pairwise_code(222).unwrap();
        assert_eq!((code.len(), Some(code.clone())), (53, b.pairwise_code(111)));
        assert_eq!(a.pairwise_code(333), None, "not in the group");
        // Before execution both still send plaintext; after op 22 frames are E2EE.
        assert_eq!(a.encrypt(b"opus"), b"opus");
        a.on_execute_transition(7);
        b.on_execute_transition(7);
        let f = a.encrypt(b"opus frame 1");
        assert!(parse_frame(&f).is_some() && f != b"opus frame 1");
        assert_eq!(b.decrypt(111, &f).unwrap(), b"opus frame 1");
        assert!(b.decrypt(111, &f).is_none(), "replayed nonce");
        assert!(b.decrypt(222, &f).is_none(), "wrong sender's key");
        assert_eq!(b.decrypt(111, &OPUS_SILENCE).unwrap(), OPUS_SILENCE);
        b.passthrough_until = None;
        assert!(b.decrypt(111, b"plain opus").is_none(), "plaintext refused once E2EE is on");
        let fb = b.encrypt(b"from b");
        assert_eq!(a.decrypt(222, &fb).unwrap(), b"from b");
        // C joins: gateway proposes the add to A and B; B's commit wins this time.
        let mut c = Dave::new(333, 999);
        let kpc = kp_of(&c.on_session_description(1));
        c.on_external_sender(&es_payload).unwrap();
        c.on_clients_connect(&[111, 222, 333]);
        let g1 = a.group().unwrap().clone();
        let msg = gw.append(&[gw.proposal(&g1, Proposal::Add(kpc.clone()))]);
        a.on_proposals(&msg).unwrap();
        let cw = binary(&b.on_proposals(&msg).unwrap(), 28).unwrap();
        let mut r = R::new(&cw);
        PublicMessage::read(&mut r).unwrap();
        let (commit, welcome) = cw.split_at(r.i);
        let mut ann = 8u16.to_be_bytes().to_vec();
        ann.extend_from_slice(commit);
        assert!(a.on_announce_commit(&ann).0.unwrap().joined == [333]);
        assert!(b.on_announce_commit(&ann).0.is_some(), "B adopts its own cached commit");
        let mut wel = 8u16.to_be_bytes().to_vec();
        wel.extend_from_slice(welcome);
        assert!(c.on_welcome(&wel).0.is_some(), "{:?}", c.errors);
        // Old-epoch frames from A still decrypt on B during the transition.
        let late = a.encrypt(b"late frame");
        for d in [&mut a, &mut b, &mut c] {
            d.on_execute_transition(8);
        }
        assert_eq!(b.decrypt(111, &late).unwrap(), b"late frame");
        let f = a.encrypt(b"epoch 2");
        assert_eq!(c.decrypt(111, &f).unwrap(), b"epoch 2");
        assert_eq!(b.decrypt(111, &f).unwrap(), b"epoch 2");
        // A leaves: remove proposal, C commits (with a path), B follows.
        let g2 = b.group().unwrap().clone();
        let a_leaf = g2.members().find(|(_, l)| user_of(&l.cred) == Some(111)).unwrap().0;
        let msg = gw.append(&[gw.proposal(&g2, Proposal::Remove(a_leaf))]);
        b.on_client_disconnect(111);
        b.on_proposals(&msg).unwrap();
        let cw = binary(&c.on_proposals(&msg).unwrap(), 28).unwrap();
        let mut ann = 9u16.to_be_bytes().to_vec();
        ann.extend_from_slice(&cw);
        assert_eq!(b.on_announce_commit(&ann).0.unwrap().left, [111]);
        assert!(c.on_announce_commit(&ann).0.is_some());
        let (_, out) = a.on_announce_commit(&ann);
        assert!(matches!(&out[0], Out::Json(v) if v["op"] == 31), "A, removed, reports and re-keys");
        assert!(binary(&out, 26).is_some());
        assert_eq!(b.verification_code(), c.verification_code());
        // An add for a user the gateway never announced is refused.
        let mut d = Dave::new(444, 999);
        let kpd = kp_of(&d.on_session_description(1));
        let g3 = b.group().unwrap().clone();
        assert!(b.on_proposals(&gw.append(&[gw.proposal(&g3, Proposal::Add(kpd))])).unwrap_err().contains("unexpected user"));
        // Sole-member reset: prepare_epoch(1) + transition 0 → back to a pending group and plaintext-free key package.
        let out = b.on_prepare_epoch(1, 1);
        assert!(binary(&out, 26).is_some() && b.group().is_none());
    }
}
