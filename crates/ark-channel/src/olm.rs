//! Olm (`m.olm.v1.curve25519-aes-sha2`) and Megolm (`m.megolm.v1.aes-sha2`),
//! written from the matrix-org/olm specifications (`docs/olm.md`,
//! `docs/megolm.md`) and checked against libolm / vodozemac wire formats.
//!
//! Olm: triple Diffie-Hellman over Curve25519 (`I_A·E_B ‖ E_A·I_B ‖ E_A·E_B`),
//! `HKDF(∅, S, "OLM_ROOT")` → root + chain key, then a double ratchet
//! (`HKDF(root, ECDH, "OLM_RATCHET")` per new ratchet key; chain step
//! `HMAC(C, 0x02)`, message key `HMAC(C, 0x01)`). Message keys expand with
//! `HKDF(∅, M, "OLM_KEYS")` into AES-256-CBC key, HMAC key and IV; the message
//! (version 3 + protobuf fields) carries an 8-byte truncated HMAC-SHA256.
//! At most 5 receiver chains, 40 skipped message keys, a 2000-message gap.
//! Megolm: a 4×32-byte hash ratchet keyed by counter bytes, `HKDF(∅, R,
//! "MEGOLM_KEYS")`, CBC + 8-byte MAC + Ed25519 signature over every message.
//! Everything here is pure; persistence is serde (the caller encrypts it).

use ark_net::crypto::{ct_eq, ed25519_verify, hmac_sha256, random_bytes, sha256, x25519, Aes};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};

pub const MAX_RECEIVER_CHAINS: usize = 5;
pub const MAX_SKIPPED_KEYS: usize = 40;
pub const MAX_MESSAGE_GAP: u32 = 2000;
const VERSION: u8 = 3;

/// Unpadded standard base64 (Matrix's encoding for keys, signatures, ciphertext).
pub fn b64(d: &[u8]) -> String {
    STANDARD_NO_PAD.encode(d)
}

/// Accepts padded or unpadded standard base64.
pub fn unb64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    STANDARD_NO_PAD.decode(s).ok().or_else(|| STANDARD.decode(s).ok())
}

pub fn key32(s: &str) -> Option<[u8; 32]> {
    unb64(s)?.try_into().ok()
}

fn rand32() -> [u8; 32] {
    random_bytes(32).try_into().unwrap()
}

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    struct L(usize);
    impl ring::hkdf::KeyType for L {
        fn len(&self) -> usize {
            self.0
        }
    }
    let mut out = vec![0u8; len];
    ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt).extract(ikm).expand(&[info], L(len)).expect("hkdf length").fill(&mut out).expect("hkdf fill");
    out
}

#[derive(Debug, Clone, PartialEq)]
pub enum OlmError {
    Format(&'static str),
    Mac,
    Signature,
    UnknownKey,
    UnknownIndex,
    Gap,
}

impl std::fmt::Display for OlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OlmError::Format(w) => write!(f, "bad message format ({w})"),
            OlmError::Mac => write!(f, "bad message MAC"),
            OlmError::Signature => write!(f, "bad signature"),
            OlmError::UnknownKey => write!(f, "unknown one-time key"),
            OlmError::UnknownIndex => write!(f, "unknown message index"),
            OlmError::Gap => write!(f, "message gap too large"),
        }
    }
}

// ───────────── protobuf-ish encoding ─────────────

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_bytes(out: &mut Vec<u8>, field: u8, b: &[u8]) {
    out.push(field << 3 | 2);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_int(out: &mut Vec<u8>, field: u8, v: u64) {
    out.push(field << 3);
    varint(out, v);
}

enum Field<'a> {
    Int(u64),
    Bytes(&'a [u8]),
}

/// Fields after the version byte; unknown fields are skipped, as libolm does.
fn fields(b: &[u8]) -> Result<Vec<(u8, Field<'_>)>, OlmError> {
    let read_varint = |i: &mut usize| -> Result<u64, OlmError> {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let byte = *b.get(*i).ok_or(OlmError::Format("truncated varint"))?;
            *i += 1;
            if shift < 64 {
                v |= ((byte & 0x7f) as u64) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
    };
    let (mut i, mut out) = (0, vec![]);
    while i < b.len() {
        let tag = read_varint(&mut i)?;
        match tag & 7 {
            0 => out.push(((tag >> 3) as u8, Field::Int(read_varint(&mut i)?))),
            2 => {
                let n = read_varint(&mut i)? as usize;
                let v = b.get(i..i.checked_add(n).ok_or(OlmError::Format("length"))?).ok_or(OlmError::Format("truncated field"))?;
                i += n;
                out.push(((tag >> 3) as u8, Field::Bytes(v)));
            }
            _ => return Err(OlmError::Format("wire type")),
        }
    }
    Ok(out)
}

fn bytes_field<'a>(f: &[(u8, Field<'a>)], n: u8) -> Option<&'a [u8]> {
    f.iter().rev().find_map(|(k, v)| match v {
        Field::Bytes(b) if *k == n => Some(*b),
        _ => None,
    })
}

fn int_field(f: &[(u8, Field)], n: u8) -> Option<u64> {
    f.iter().rev().find_map(|(k, v)| match v {
        Field::Int(x) if *k == n => Some(*x),
        _ => None,
    })
}

/// (AES key, HMAC key, IV) from a message key / Megolm ratchet.
fn cipher_keys(secret: &[u8], info: &[u8]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let k = hkdf(&[], secret, info, 80);
    (k[..32].try_into().unwrap(), k[32..64].try_into().unwrap(), k[64..].try_into().unwrap())
}

// ───────────── keys ─────────────

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Curve {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

impl Curve {
    pub fn generate() -> Curve {
        Curve::from_secret(rand32())
    }
    pub fn from_secret(secret: [u8; 32]) -> Curve {
        Curve { public: x25519::public_key(&secret), secret }
    }
    pub(crate) fn dh(&self, peer: &[u8; 32]) -> [u8; 32] {
        x25519::scalarmult(&self.secret, peer)
    }
}

pub fn ed25519_pair(seed: &[u8; 32]) -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 seed")
}

pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    use ring::signature::KeyPair;
    ed25519_pair(seed).public_key().as_ref().try_into().unwrap()
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OneTimeKey {
    pub id: u32,
    pub key: Curve,
    pub published: bool,
}

/// Matrix key id for a counter: base64 of the big-endian u32, as libolm.
pub fn key_id(id: u32) -> String {
    b64(&id.to_be_bytes())
}

/// A device's long-term identity plus its one-time and fallback keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub ed_seed: [u8; 32],
    pub identity: Curve,
    pub one_time: Vec<OneTimeKey>,
    pub fallback: Option<OneTimeKey>,
    pub prev_fallback: Option<OneTimeKey>,
    pub next_id: u32,
}

pub const MAX_ONE_TIME_KEYS: usize = 100;

impl Account {
    pub fn generate() -> Account {
        Account::from_secrets(rand32(), rand32())
    }
    pub fn from_secrets(ed_seed: [u8; 32], curve_secret: [u8; 32]) -> Account {
        Account { ed_seed, identity: Curve::from_secret(curve_secret), one_time: vec![], fallback: None, prev_fallback: None, next_id: 1 }
    }
    pub fn ed25519(&self) -> String {
        b64(&ed25519_public(&self.ed_seed))
    }
    pub fn curve25519(&self) -> String {
        b64(&self.identity.public)
    }
    pub fn sign(&self, msg: &[u8]) -> String {
        b64(ed25519_pair(&self.ed_seed).sign(msg).as_ref())
    }
    /// New unpublished one-time keys; the oldest are dropped beyond 100 (libolm's limit).
    pub fn generate_one_time_keys(&mut self, n: usize) {
        for _ in 0..n {
            self.one_time.push(OneTimeKey { id: self.next_id, key: Curve::generate(), published: false });
            self.next_id += 1;
        }
        let extra = self.one_time.len().saturating_sub(MAX_ONE_TIME_KEYS);
        self.one_time.drain(..extra);
    }
    /// Rotate the fallback key, keeping the previous one for in-flight pre-key messages.
    pub fn generate_fallback_key(&mut self) {
        let new = OneTimeKey { id: self.next_id, key: Curve::generate(), published: false };
        self.next_id += 1;
        self.prev_fallback = self.fallback.replace(new);
    }
    /// Outbound session to a device with identity key `their_identity` and a claimed one-time key.
    pub fn outbound_session(&self, their_identity: &[u8; 32], their_one_time: &[u8; 32]) -> Session {
        Session::outbound(&self.identity, Curve::generate(), Curve::generate(), their_identity, their_one_time)
    }
    /// New inbound session from a pre-key message; consumes the one-time key on success.
    pub fn inbound_session(&mut self, prekey: &[u8]) -> Result<(Session, Vec<u8>), OlmError> {
        let p = PreKey::parse(prekey)?;
        let otk = self.one_time.iter().chain(&self.fallback).chain(&self.prev_fallback).find(|k| k.key.public == p.one_time).ok_or(OlmError::UnknownKey)?;
        let mut s = Session::inbound(&self.identity, &otk.key, &p)?;
        let plain = s.decrypt(&p.message)?;
        let id = otk.id;
        self.one_time.retain(|k| k.id != id);
        Ok((s, plain))
    }
}

// ───────────── Olm messages ─────────────

#[derive(Debug, PartialEq)]
pub struct Message {
    pub ratchet: [u8; 32],
    pub index: u32,
    pub ciphertext: Vec<u8>,
}

impl Message {
    fn encode(ratchet: &[u8; 32], index: u32, ciphertext: &[u8], mac_key: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![VERSION];
        put_bytes(&mut out, 1, ratchet);
        put_int(&mut out, 2, index as u64);
        put_bytes(&mut out, 4, ciphertext);
        let mac = hmac_sha256(mac_key, &out);
        out.extend_from_slice(&mac[..8]);
        out
    }
    /// (message, MAC'd bytes, MAC).
    fn parse(b: &[u8]) -> Result<(Message, &[u8], &[u8]), OlmError> {
        if b.len() < 9 || b[0] != VERSION {
            return Err(OlmError::Format("version"));
        }
        let (body, mac) = b.split_at(b.len() - 8);
        let f = fields(&body[1..])?;
        let ratchet: [u8; 32] = bytes_field(&f, 1).and_then(|r| r.try_into().ok()).ok_or(OlmError::Format("ratchet key"))?;
        let index = int_field(&f, 2).ok_or(OlmError::Format("counter"))?.try_into().map_err(|_| OlmError::Format("counter"))?;
        let ciphertext = bytes_field(&f, 4).ok_or(OlmError::Format("ciphertext"))?.to_vec();
        Ok((Message { ratchet, index, ciphertext }, body, mac))
    }
}

pub struct PreKey {
    pub one_time: [u8; 32],
    pub base: [u8; 32],
    pub identity: [u8; 32],
    pub message: Vec<u8>,
}

impl PreKey {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        put_bytes(&mut out, 1, &self.one_time);
        put_bytes(&mut out, 2, &self.base);
        put_bytes(&mut out, 3, &self.identity);
        put_bytes(&mut out, 4, &self.message);
        out
    }
    pub fn parse(b: &[u8]) -> Result<PreKey, OlmError> {
        if b.first() != Some(&VERSION) {
            return Err(OlmError::Format("version"));
        }
        let f = fields(&b[1..])?;
        let k = |n| bytes_field(&f, n).and_then(|r| r.try_into().ok()).ok_or(OlmError::Format("pre-key field"));
        Ok(PreKey { one_time: k(1)?, base: k(2)?, identity: k(3)?, message: bytes_field(&f, 4).ok_or(OlmError::Format("message"))?.to_vec() })
    }
}

fn olm_encrypt(mk: &[u8; 32], ratchet: &[u8; 32], index: u32, plain: &[u8]) -> Vec<u8> {
    let (ak, hk, iv) = cipher_keys(mk, b"OLM_KEYS");
    Message::encode(ratchet, index, &Aes::new(&ak).unwrap().cbc_encrypt(&iv, plain), &hk)
}

fn olm_decrypt(mk: &[u8; 32], raw: &[u8]) -> Result<Vec<u8>, OlmError> {
    let (m, body, mac) = Message::parse(raw)?;
    let (ak, hk, iv) = cipher_keys(mk, b"OLM_KEYS");
    if !ct_eq(&hmac_sha256(&hk, body)[..8], mac) {
        return Err(OlmError::Mac);
    }
    Aes::new(&ak).unwrap().cbc_decrypt(&iv, &m.ciphertext).ok_or(OlmError::Format("padding"))
}

fn chain_step(c: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(c, &[2])
}
fn message_key(c: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(c, &[1])
}

/// (root, chain) after a ratchet step.
fn ratchet_kdf(root: &[u8; 32], shared: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let k = hkdf(root, shared, b"OLM_RATCHET", 64);
    (k[..32].try_into().unwrap(), k[32..].try_into().unwrap())
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SenderChain {
    pub ratchet: Curve,
    pub chain: [u8; 32],
    pub index: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ReceiverChain {
    pub ratchet: [u8; 32],
    pub chain: [u8; 32],
    pub index: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SkippedKey {
    pub ratchet: [u8; 32],
    pub index: u32,
    pub key: [u8; 32],
}

/// One Olm session (double ratchet) with a peer device.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Session {
    pub root: [u8; 32],
    pub sender: Option<SenderChain>,
    /// Newest first.
    pub receivers: Vec<ReceiverChain>,
    pub skipped: Vec<SkippedKey>,
    /// Alice's identity key, Alice's base key, Bob's one-time key.
    pub alice_identity: [u8; 32],
    pub alice_base: [u8; 32],
    pub bob_one_time: [u8; 32],
    /// We created it (we send pre-key messages until the peer answers).
    pub outbound: bool,
    pub received: bool,
    #[serde(default)]
    pub last_used: u64,
}

impl Session {
    fn root_kdf(secret: &[u8]) -> ([u8; 32], [u8; 32]) {
        let k = hkdf(&[], secret, b"OLM_ROOT", 64);
        (k[..32].try_into().unwrap(), k[32..].try_into().unwrap())
    }

    /// Alice's side, with explicit base and first ratchet keys (deterministic in tests).
    pub fn outbound(identity: &Curve, base: Curve, ratchet: Curve, their_identity: &[u8; 32], their_one_time: &[u8; 32]) -> Session {
        let s = [identity.dh(their_one_time), base.dh(their_identity), base.dh(their_one_time)].concat();
        let (root, chain) = Session::root_kdf(&s);
        Session { root, sender: Some(SenderChain { ratchet, chain, index: 0 }), receivers: vec![], skipped: vec![], alice_identity: identity.public, alice_base: base.public, bob_one_time: *their_one_time, outbound: true, received: false, last_used: 0 }
    }

    fn inbound(identity: &Curve, one_time: &Curve, p: &PreKey) -> Result<Session, OlmError> {
        let (m, _, _) = Message::parse(&p.message)?;
        let s = [one_time.dh(&p.identity), identity.dh(&p.base), one_time.dh(&p.base)].concat();
        let (root, chain) = Session::root_kdf(&s);
        Ok(Session { root, sender: None, receivers: vec![ReceiverChain { ratchet: m.ratchet, chain, index: 0 }], skipped: vec![], alice_identity: p.identity, alice_base: p.base, bob_one_time: p.one_time, outbound: false, received: true, last_used: 0 })
    }

    /// `SHA-256(I_A ‖ E_A ‖ E_B)`, as libolm's session id.
    pub fn id(&self) -> String {
        b64(&sha256(&[self.alice_identity, self.alice_base, self.bob_one_time].concat()))
    }

    /// Does this pre-key message belong to this (inbound) session?
    pub fn matches(&self, prekey: &[u8]) -> bool {
        PreKey::parse(prekey).is_ok_and(|p| p.identity == self.alice_identity && p.base == self.alice_base && p.one_time == self.bob_one_time)
    }

    /// `(type, bytes)`: 0 = pre-key message, 1 = normal message.
    pub fn encrypt(&mut self, plain: &[u8]) -> (u8, Vec<u8>) {
        if self.sender.is_none() {
            let r = Curve::generate();
            let their = self.receivers.first().map(|c| c.ratchet).unwrap_or_default();
            let (root, chain) = ratchet_kdf(&self.root, &r.dh(&their));
            self.root = root;
            self.sender = Some(SenderChain { ratchet: r, chain, index: 0 });
        }
        let s = self.sender.as_mut().unwrap();
        let msg = olm_encrypt(&message_key(&s.chain), &s.ratchet.public, s.index, plain);
        s.chain = chain_step(&s.chain);
        s.index += 1;
        if self.outbound && !self.received {
            (0, PreKey { one_time: self.bob_one_time, base: self.alice_base, identity: self.alice_identity, message: msg }.encode())
        } else {
            (1, msg)
        }
    }

    /// Decrypt a normal message (or the inner message of a pre-key message).
    /// State changes only when the MAC verifies.
    pub fn decrypt(&mut self, raw: &[u8]) -> Result<Vec<u8>, OlmError> {
        let (m, _, _) = Message::parse(raw)?;
        let advance = |chain: [u8; 32], from: u32, ratchet: [u8; 32]| -> Result<([u8; 32], Vec<SkippedKey>), OlmError> {
            if m.index - from > MAX_MESSAGE_GAP {
                return Err(OlmError::Gap);
            }
            let (mut c, mut skipped) = (chain, vec![]);
            for i in from..m.index {
                skipped.push(SkippedKey { ratchet, index: i, key: message_key(&c) });
                c = chain_step(&c);
            }
            Ok((c, skipped))
        };
        let plain = if let Some(ci) = self.receivers.iter().position(|c| c.ratchet == m.ratchet) {
            let c = self.receivers[ci].clone();
            if m.index < c.index {
                let si = self.skipped.iter().position(|k| k.ratchet == m.ratchet && k.index == m.index).ok_or(OlmError::UnknownIndex)?;
                let plain = olm_decrypt(&self.skipped[si].key, raw)?;
                self.skipped.remove(si);
                plain
            } else {
                let (chain, skipped) = advance(c.chain, c.index, c.ratchet)?;
                let plain = olm_decrypt(&message_key(&chain), raw)?;
                self.receivers[ci].chain = chain_step(&chain);
                self.receivers[ci].index = m.index + 1;
                self.push_skipped(skipped);
                plain
            }
        } else {
            let ours = self.sender.as_ref().ok_or(OlmError::Format("unexpected ratchet key"))?;
            let (root, chain0) = ratchet_kdf(&self.root, &ours.ratchet.dh(&m.ratchet));
            let (chain, skipped) = advance(chain0, 0, m.ratchet)?;
            let plain = olm_decrypt(&message_key(&chain), raw)?;
            self.root = root;
            self.receivers.insert(0, ReceiverChain { ratchet: m.ratchet, chain: chain_step(&chain), index: m.index + 1 });
            self.receivers.truncate(MAX_RECEIVER_CHAINS);
            self.sender = None;
            self.push_skipped(skipped);
            plain
        };
        self.received = true;
        Ok(plain)
    }

    fn push_skipped(&mut self, k: Vec<SkippedKey>) {
        self.skipped.extend(k);
        let extra = self.skipped.len().saturating_sub(MAX_SKIPPED_KEYS);
        self.skipped.drain(..extra);
    }
}

// ───────────── Megolm ─────────────

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Ratchet {
    pub parts: [[u8; 32]; 4],
    pub counter: u32,
}

impl Ratchet {
    fn rehash(&mut self, from: usize, to: usize) {
        self.parts[to] = hmac_sha256(&self.parts[from], &[to as u8]);
    }

    pub fn advance(&mut self) {
        self.counter = self.counter.wrapping_add(1);
        let (mut h, mut mask) = (0, 0x00FF_FFFFu32);
        while h < 4 && self.counter & mask != 0 {
            h += 1;
            mask >>= 8;
        }
        for i in (h..4).rev() {
            self.rehash(h, i);
        }
    }

    /// libolm `megolm_advance_to`: O(256·4) hashes at most.
    pub fn advance_to(&mut self, to: u32) {
        for j in 0..4 {
            let shift = (3 - j) * 8;
            let mask = !0u32 << shift;
            let mut steps = ((to >> shift).wrapping_sub(self.counter >> shift)) & 0xff;
            if steps == 0 {
                if to < self.counter {
                    steps = 0x100;
                } else {
                    continue;
                }
            }
            for _ in 1..steps {
                self.rehash(j, j);
            }
            for k in (j..4).rev() {
                self.rehash(j, k);
            }
            self.counter = to & mask;
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.parts.concat()
    }

    fn from_bytes(counter: u32, b: &[u8]) -> Ratchet {
        let mut parts = [[0u8; 32]; 4];
        for (i, p) in parts.iter_mut().enumerate() {
            p.copy_from_slice(&b[32 * i..32 * i + 32]);
        }
        Ratchet { parts, counter }
    }
}

/// Our sending side of a room session.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupOutbound {
    pub ratchet: Ratchet,
    pub ed_seed: [u8; 32],
}

impl GroupOutbound {
    pub fn generate() -> GroupOutbound {
        let r = random_bytes(128);
        GroupOutbound { ratchet: Ratchet::from_bytes(0, &r), ed_seed: rand32() }
    }
    pub fn id(&self) -> String {
        b64(&ed25519_public(&self.ed_seed))
    }
    pub fn index(&self) -> u32 {
        self.ratchet.counter
    }
    /// `m.room_key` session key: `0x02 ‖ index ‖ R ‖ Ed25519 pub ‖ signature`.
    pub fn session_key(&self) -> String {
        let mut b = vec![2u8];
        b.extend_from_slice(&self.ratchet.counter.to_be_bytes());
        b.extend(self.ratchet.bytes());
        b.extend_from_slice(&ed25519_public(&self.ed_seed));
        let sig = ed25519_pair(&self.ed_seed).sign(&b);
        b.extend_from_slice(sig.as_ref());
        b64(&b)
    }
    pub fn encrypt(&mut self, plain: &[u8]) -> String {
        let (ak, hk, iv) = cipher_keys(&self.ratchet.bytes(), b"MEGOLM_KEYS");
        let mut out = vec![VERSION];
        put_int(&mut out, 1, self.ratchet.counter as u64);
        put_bytes(&mut out, 2, &Aes::new(&ak).unwrap().cbc_encrypt(&iv, plain));
        let mac = hmac_sha256(&hk, &out);
        out.extend_from_slice(&mac[..8]);
        let sig = ed25519_pair(&self.ed_seed).sign(&out);
        out.extend_from_slice(sig.as_ref());
        self.ratchet.advance();
        b64(&out)
    }
}

/// A room session received from someone (the earliest ratchet state we know).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GroupInbound {
    pub ratchet: Ratchet,
    pub signing: [u8; 32],
}

impl GroupInbound {
    /// From an `m.room_key` session key (v2, signed) or an exported key (v1, unsigned).
    pub fn from_session_key(s: &str) -> Result<GroupInbound, OlmError> {
        let b = unb64(s).ok_or(OlmError::Format("base64"))?;
        match b.first() {
            Some(2) if b.len() == 229 => {
                if !ed25519_verify(&b[133..165], &b[..165], &b[165..]) {
                    return Err(OlmError::Signature);
                }
            }
            Some(1) if b.len() == 165 => {}
            _ => return Err(OlmError::Format("session key")),
        }
        Ok(GroupInbound { ratchet: Ratchet::from_bytes(u32::from_be_bytes(b[1..5].try_into().unwrap()), &b[5..133]), signing: b[133..165].try_into().unwrap() })
    }
    pub fn id(&self) -> String {
        b64(&self.signing)
    }
    pub fn first_index(&self) -> u32 {
        self.ratchet.counter
    }
    /// Exported session key (v1, unsigned) at our earliest index: `0x01 ‖ index ‖ R ‖ Ed25519 pub`,
    /// as in `m.forwarded_room_key` and key backups.
    pub fn export(&self) -> String {
        let mut b = vec![1u8];
        b.extend_from_slice(&self.ratchet.counter.to_be_bytes());
        b.extend(self.ratchet.bytes());
        b.extend_from_slice(&self.signing);
        b64(&b)
    }
    /// (plaintext, message index).
    pub fn decrypt(&self, ciphertext: &str) -> Result<(Vec<u8>, u32), OlmError> {
        let b = unb64(ciphertext).ok_or(OlmError::Format("base64"))?;
        if b.len() < 1 + 8 + 64 || b[0] != VERSION {
            return Err(OlmError::Format("version"));
        }
        let (signed, sig) = b.split_at(b.len() - 64);
        if !ed25519_verify(&self.signing, signed, sig) {
            return Err(OlmError::Signature);
        }
        let (body, mac) = signed.split_at(signed.len() - 8);
        let f = fields(&body[1..])?;
        let index: u32 = int_field(&f, 1).ok_or(OlmError::Format("index"))?.try_into().map_err(|_| OlmError::Format("index"))?;
        let ct = bytes_field(&f, 2).ok_or(OlmError::Format("ciphertext"))?;
        if index < self.ratchet.counter {
            return Err(OlmError::UnknownIndex);
        }
        let mut r = self.ratchet.clone();
        r.advance_to(index);
        let (ak, hk, iv) = cipher_keys(&r.bytes(), b"MEGOLM_KEYS");
        if !ct_eq(&hmac_sha256(&hk, body)[..8], mac) {
            return Err(OlmError::Mac);
        }
        Ok((Aes::new(&ak).unwrap().cbc_decrypt(&iv, ct).ok_or(OlmError::Format("padding"))?, index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(b: u8) -> Curve {
        Curve::from_secret([b; 32])
    }

    #[test]
    fn message_encoding_matches_libolm_test_message() {
        // libolm tests/test_message.cpp: ratchet "ratchetkeyhere", counter 1, ciphertext "ciphertexthere".
        let mut out = vec![3u8];
        put_bytes(&mut out, 1, b"ratchetkeyhere");
        put_int(&mut out, 2, 1);
        put_bytes(&mut out, 4, b"ciphertexthere");
        assert_eq!(out, b"\x03\n\x0Eratchetkeyhere\x10\x01\"\x0Eciphertexthere");
        let f = fields(&out[1..]).unwrap();
        assert_eq!((bytes_field(&f, 1), int_field(&f, 2), bytes_field(&f, 4)), (Some(&b"ratchetkeyhere"[..]), Some(1), Some(&b"ciphertexthere"[..])));
        let mut v = vec![];
        varint(&mut v, 300);
        assert_eq!(v, [0xac, 0x02]);
        assert!(fields(&[0x0a, 0x05, 1]).is_err(), "truncated");
        assert!(fields(&[0x0b]).is_err(), "bad wire type");
    }

    #[test]
    fn olm_round_trip_ratchets_and_rejects_tampering() {
        let mut bob = Account::from_secrets([1; 32], [2; 32]);
        bob.generate_one_time_keys(2);
        let otk = bob.one_time[0].key.public;
        let alice = Account::from_secrets([3; 32], [4; 32]);
        let mut a = alice.outbound_session(&bob.identity.public, &otk);
        let (t, m1) = a.encrypt(b"hello bob");
        assert_eq!(t, 0);
        let (t2, m2) = a.encrypt(b"second pre-key");
        assert_eq!(t2, 0, "pre-key until Bob answers");
        let (mut b, p) = bob.inbound_session(&m1).unwrap();
        assert_eq!(p, b"hello bob");
        assert_eq!(bob.one_time.len(), 1, "one-time key consumed");
        assert!(bob.inbound_session(&m1).is_err(), "one-time key gone");
        assert!(b.matches(&m2) && b.id() == a.id());
        assert_eq!(b.decrypt(&PreKey::parse(&m2).unwrap().message).unwrap(), b"second pre-key");
        // Bob answers on a new ratchet; Alice switches to normal messages.
        let (t, r1) = b.encrypt(b"hi alice");
        assert_eq!(t, 1);
        assert_eq!(a.decrypt(&r1).unwrap(), b"hi alice");
        let (t, m3) = a.encrypt(b"normal now");
        assert_eq!(t, 1);
        // Out of order within a chain: skipped keys.
        let (_, m4) = a.encrypt(b"four");
        let (_, m5) = a.encrypt(b"five");
        assert_eq!(b.decrypt(&m5).unwrap(), b"five");
        assert_eq!(b.decrypt(&m3).unwrap(), b"normal now");
        assert_eq!(b.decrypt(&m4).unwrap(), b"four");
        assert_eq!(b.decrypt(&m4), Err(OlmError::UnknownIndex), "replay rejected");
        // Tampering: MAC failure leaves state untouched.
        let (_, mut m6) = a.encrypt(b"six");
        let n = m6.len();
        m6[n - 12] ^= 1;
        let before = format!("{b:?}");
        assert_eq!(b.decrypt(&m6), Err(OlmError::Mac));
        assert_eq!(before, format!("{b:?}"));
        // Many round trips with fresh ratchets each time.
        for i in 0..20 {
            let (_, x) = a.encrypt(format!("a{i}").as_bytes());
            assert_eq!(b.decrypt(&x).unwrap(), format!("a{i}").as_bytes());
            let (_, y) = b.encrypt(format!("b{i}").as_bytes());
            assert_eq!(a.decrypt(&y).unwrap(), format!("b{i}").as_bytes());
        }
        assert!(b.receivers.len() <= MAX_RECEIVER_CHAINS);
        // Serde round trip keeps the session usable.
        let mut b2: Session = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        let (_, z) = a.encrypt(b"after pickle");
        assert_eq!(b2.decrypt(&z).unwrap(), b"after pickle");
        // Gap limit.
        let mut far = a.clone();
        far.sender.as_mut().unwrap().index += MAX_MESSAGE_GAP + 5;
        let (_, g) = far.encrypt(b"x");
        assert_eq!(b2.decrypt(&g), Err(OlmError::Gap));
    }

    #[test]
    fn fallback_key_is_not_consumed() {
        let mut bob = Account::from_secrets([5; 32], [6; 32]);
        bob.generate_fallback_key();
        let fb = bob.fallback.as_ref().unwrap().key.public;
        let alice = Account::from_secrets([7; 32], [8; 32]);
        for _ in 0..2 {
            let (_, m) = alice.outbound_session(&bob.identity.public, &fb).encrypt(b"x");
            assert_eq!(bob.inbound_session(&m).unwrap().1, b"x");
        }
        bob.generate_fallback_key();
        let (_, m) = alice.outbound_session(&bob.identity.public, &fb).encrypt(b"old fallback");
        assert_eq!(bob.inbound_session(&m).unwrap().1, b"old fallback", "previous fallback still accepted");
    }

    #[test]
    fn olm_deterministic_vector() {
        // Fixed keys → fixed shared secret; pins the 3DH order and KDF labels
        // (cross-checked against vodozemac in the interop run, see matrix_e2ee tests).
        let (ai, ab, ar, bi, bo) = (c(0x11), c(0x22), c(0x33), c(0x44), c(0x55));
        let mut a = Session::outbound(&ai, ab.clone(), ar.clone(), &bi.public, &bo.public);
        let (_, m) = a.encrypt(b"vector");
        let p = PreKey::parse(&m).unwrap();
        assert_eq!((p.identity, p.base, p.one_time), (ai.public, ab.public, bo.public));
        let s = [ai.dh(&bo.public), ab.dh(&bi.public), ab.dh(&bo.public)].concat();
        let (root, chain) = Session::root_kdf(&s);
        assert_eq!(a.root, root);
        let mk = message_key(&chain);
        assert_eq!(olm_decrypt(&mk, &p.message).unwrap(), b"vector");
        let b = Session::inbound(&bi, &bo, &p).unwrap();
        assert_eq!((b.root, b.receivers[0].chain), (root, chain));
    }

    #[test]
    fn megolm_ratchet_advance_to_matches_stepping() {
        let mut base = Ratchet::from_bytes(0, &(0..128).collect::<Vec<u8>>());
        let mut stepped = base.clone();
        for target in [1u32, 2, 255, 256, 257, 0x1_0000, 0x1_0101, 0x1_FFFF] {
            while stepped.counter < target {
                stepped.advance();
            }
            let mut jumped = base.clone();
            jumped.advance_to(target);
            assert_eq!(jumped, stepped, "advance_to({target:#x})");
        }
        base.advance_to(0x0100_0000);
        assert_eq!(base.counter, 0x0100_0000);
        // One step rehashes only R(3) (R(0) changes every 2^24 steps).
        let mut one = Ratchet::from_bytes(0, &(0..128).collect::<Vec<u8>>());
        one.advance_to(1);
        assert_eq!(one.parts[0], Ratchet::from_bytes(0, &(0..128).collect::<Vec<u8>>()).parts[0]);
        assert_eq!(one.parts[3], hmac_sha256(&(96..128).collect::<Vec<u8>>(), &[3]));
    }

    #[test]
    fn megolm_round_trip_signature_and_index() {
        let mut out = GroupOutbound::generate();
        let key0 = out.session_key();
        let c0 = out.encrypt(b"zero");
        let c1 = out.encrypt(b"one");
        let late = GroupInbound::from_session_key(&out.session_key()).unwrap();
        let exported = GroupInbound::from_session_key(&late.export()).unwrap();
        assert_eq!((exported.id(), exported.first_index(), exported.ratchet.clone()), (late.id(), 2, late.ratchet.clone()));
        let c2 = out.encrypt(b"two");
        let inb = GroupInbound::from_session_key(&key0).unwrap();
        assert_eq!(inb.id(), out.id());
        assert_eq!(inb.decrypt(&c1).unwrap(), (b"one".to_vec(), 1));
        assert_eq!(inb.decrypt(&c0).unwrap(), (b"zero".to_vec(), 0));
        assert_eq!(inb.decrypt(&c2).unwrap(), (b"two".to_vec(), 2));
        assert_eq!(late.first_index(), 2);
        assert_eq!(late.decrypt(&c0), Err(OlmError::UnknownIndex));
        let mut bad = unb64(&c2).unwrap();
        bad[3] ^= 1;
        assert_eq!(inb.decrypt(&b64(&bad)), Err(OlmError::Signature));
        let mut k = unb64(&key0).unwrap();
        k[10] ^= 1;
        assert_eq!(GroupInbound::from_session_key(&b64(&k)).unwrap_err(), OlmError::Signature);
        for _ in 0..300 {
            out.encrypt(b"x");
        }
        assert_eq!(inb.decrypt(&out.encrypt(b"far")).unwrap(), (b"far".to_vec(), 303));
    }
}
