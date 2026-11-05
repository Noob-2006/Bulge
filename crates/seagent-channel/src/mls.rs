//! The subset of MLS 1.0 (RFC 9420) that Discord's DAVE protocol needs, for
//! cipher suite 2 only (MLS_128_DHKEMP256_AES128GCM_SHA256_P256): TLS-style
//! codec with MLS varint lengths, HPKE base mode (RFC 9180, DHKEM(P-256) via
//! `p256`, HKDF-SHA256, AES-128-GCM via ring), ECDSA P-256 signatures (ring,
//! DER), the array ratchet tree (resolution, filtered direct paths, tree and
//! parent hashes), the key schedule and transcript hashes, PublicMessage
//! framing (signature + membership tag), KeyPackages, joining by Welcome
//! (tree hash, leaf signatures and parent-hash validity checked), processing
//! Commits (Add / Remove / Update / PreSharedKey / GroupContextExtensions
//! proposals, inline or by reference, UpdatePath decryption) and creating
//! Commits with UpdatePath and Welcome. Not implemented: PrivateMessage,
//! application messages, external commits, ReInit / branch, other suites.
//! Verified against the mlswg/mls-implementations test vectors (see tests).

use seagent_net::crypto::{hmac_sha256, random_bytes, sha256};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use std::collections::BTreeMap;
use std::sync::Arc;

pub type Res<T> = Result<T, String>;

pub const SUITE: u16 = 2;
pub const MLS10: u16 = 1;
pub const NH: usize = 32;
pub const WF_PUBLIC: u16 = 1;
pub const WF_WELCOME: u16 = 3;
pub const WF_KEY_PACKAGE: u16 = 5;
pub const EXT_RATCHET_TREE: u16 = 2;
pub const EXT_EXTERNAL_SENDERS: u16 = 5;

fn err<T>(m: impl Into<String>) -> Res<T> {
    Err(m.into())
}

// ---------------------------------------------------------------- codec

/// TLS presentation-language writer with MLS variable-length vectors.
#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn varint(&mut self, n: usize) -> &mut Self {
        match n {
            0..=63 => self.u8(n as u8),
            64..=16383 => self.u16(0x4000 | n as u16),
            _ => self.u32(0x8000_0000 | n as u32),
        }
    }
    pub fn vec(&mut self, b: &[u8]) -> &mut Self {
        self.varint(b.len());
        self.0.extend_from_slice(b);
        self
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    /// A vector whose body is written by `f`.
    pub fn nest(&mut self, f: impl FnOnce(&mut W)) -> &mut Self {
        let mut inner = W::default();
        f(&mut inner);
        self.vec(&inner.0)
    }
}

pub struct R<'a> {
    b: &'a [u8],
    pub i: usize,
}

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> R<'a> {
        R { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        if self.b.len() - self.i < n {
            return err("truncated MLS structure");
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn varint(&mut self) -> Res<usize> {
        let b0 = self.u8()?;
        let (n, min) = match b0 >> 6 {
            0 => return Ok((b0 & 0x3f) as usize),
            1 => ((((b0 & 0x3f) as usize) << 8) | self.u8()? as usize, 64),
            2 => {
                let r = self.take(3)?;
                ((((b0 & 0x3f) as usize) << 24) | (r[0] as usize) << 16 | (r[1] as usize) << 8 | r[2] as usize, 16384)
            }
            _ => return err("invalid varint prefix"),
        };
        if n < min {
            return err("non-minimal varint");
        }
        Ok(n)
    }
    pub fn vec(&mut self) -> Res<&'a [u8]> {
        let n = self.varint()?;
        self.take(n)
    }
    pub fn sub(&mut self) -> Res<R<'a>> {
        Ok(R::new(self.vec()?))
    }
    pub fn done(&self) -> bool {
        self.i == self.b.len()
    }
    pub fn since(&self, start: usize) -> &'a [u8] {
        &self.b[start..self.i]
    }
    pub fn optional(&mut self) -> Res<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => err("bad optional"),
        }
    }
    /// Every element of a vector.
    pub fn list<T>(&mut self, mut f: impl FnMut(&mut R<'a>) -> Res<T>) -> Res<Vec<T>> {
        let mut s = self.sub()?;
        let mut out = Vec::new();
        while !s.done() {
            out.push(f(&mut s)?);
        }
        Ok(out)
    }
    pub fn end(&self) -> Res<()> {
        if self.done() {
            Ok(())
        } else {
            err("trailing bytes after MLS structure")
        }
    }
}

// ---------------------------------------------------------------- crypto

pub fn hash(d: &[u8]) -> [u8; 32] {
    sha256(d)
}

pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut m = t.clone();
        m.extend_from_slice(info);
        m.push(i);
        t = hmac_sha256(prk, &m).to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(len);
    out
}

pub fn expand_with_label(secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
    let mut w = W::default();
    w.u16(len as u16).vec(format!("MLS 1.0 {label}").as_bytes()).vec(ctx);
    expand(secret, &w.0, len)
}

pub fn derive_secret(secret: &[u8], label: &str) -> Vec<u8> {
    expand_with_label(secret, label, &[], NH)
}

pub fn derive_tree_secret(secret: &[u8], label: &str, generation: u32, len: usize) -> Vec<u8> {
    expand_with_label(secret, label, &generation.to_be_bytes(), len)
}

pub fn ref_hash(label: &str, value: &[u8]) -> Vec<u8> {
    let mut w = W::default();
    w.vec(label.as_bytes()).vec(value);
    hash(&w.0).to_vec()
}

fn aead_key(key: &[u8]) -> Res<LessSafeKey> {
    Ok(LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).map_err(|_| "bad AES-128-GCM key")?))
}

pub fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
    let mut buf = pt.to_vec();
    let n = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "bad nonce")?;
    aead_key(key)?.seal_in_place_append_tag(n, Aad::from(aad), &mut buf).map_err(|_| "seal failed")?;
    Ok(buf)
}

pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
    let mut buf = ct.to_vec();
    let n = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "bad nonce")?;
    let len = aead_key(key)?.open_in_place(n, Aad::from(aad), &mut buf).map_err(|_| "AEAD authentication failed")?.len();
    buf.truncate(len);
    Ok(buf)
}

/// An ECDSA P-256 signing key (the member's MLS identity key).
pub struct Signer {
    kp: EcdsaKeyPair,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer({})", seagent_net::crypto::hex(&self.public()))
    }
}

impl Signer {
    pub fn generate() -> Signer {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("P-256 key generation");
        Signer { kp: EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).expect("own PKCS#8") }
    }
    pub fn from_scalar(sk: &[u8]) -> Res<Signer> {
        let pk = crate::p256::public_key(sk).ok_or("invalid P-256 signature key")?;
        let kp = EcdsaKeyPair::from_private_key_and_public_key(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, sk, &pk, &SystemRandom::new()).map_err(|e| format!("signature key rejected: {e}"))?;
        Ok(Signer { kp })
    }
    pub fn public(&self) -> Vec<u8> {
        self.kp.public_key().as_ref().to_vec()
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.kp.sign(&SystemRandom::new(), msg).expect("ECDSA sign").as_ref().to_vec()
    }
}

fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    let mut w = W::default();
    w.vec(format!("MLS 1.0 {label}").as_bytes()).vec(content);
    w.0
}

pub fn sign_with_label(s: &Signer, label: &str, content: &[u8]) -> Vec<u8> {
    s.sign(&sign_content(label, content))
}

pub fn verify_with_label(pk: &[u8], label: &str, content: &[u8], sig: &[u8]) -> bool {
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk).verify(&sign_content(label, content), sig).is_ok()
}

// ---------------------------------------------------------------- HPKE (RFC 9180, base mode)

const KEM_ID: u16 = 0x0010;
const HPKE_SUITE: [u8; 10] = *b"HPKE\x00\x10\x00\x01\x00\x01";
const KEM_SUITE: [u8; 5] = *b"KEM\x00\x10";

fn labeled_extract(suite: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> [u8; 32] {
    let mut m = b"HPKE-v1".to_vec();
    m.extend_from_slice(suite);
    m.extend_from_slice(label.as_bytes());
    m.extend_from_slice(ikm);
    extract(salt, &m)
}

fn labeled_expand(suite: &[u8], prk: &[u8], label: &str, info: &[u8], len: usize) -> Vec<u8> {
    let mut m = (len as u16).to_be_bytes().to_vec();
    m.extend_from_slice(b"HPKE-v1");
    m.extend_from_slice(suite);
    m.extend_from_slice(label.as_bytes());
    m.extend_from_slice(info);
    expand(prk, &m, len)
}

/// DeriveKeyPair for DHKEM(P-256) (RFC 9180 §7.1.3): rejection sampling.
pub fn derive_key_pair(ikm: &[u8]) -> ([u8; 32], Vec<u8>) {
    let prk = labeled_extract(&KEM_SUITE, b"", "dkp_prk", ikm);
    for counter in 0..=255u8 {
        let sk = labeled_expand(&KEM_SUITE, &prk, "candidate", &[counter], 32);
        if crate::p256::valid_scalar(&sk) {
            let pk = crate::p256::public_key(&sk).unwrap();
            return (sk.try_into().unwrap(), pk.to_vec());
        }
    }
    unreachable!("DeriveKeyPair: 256 rejected candidates")
}

pub fn generate_key_pair() -> ([u8; 32], Vec<u8>) {
    derive_key_pair(&random_bytes(32))
}

fn kem_shared(dh: &[u8], enc: &[u8], pk_r: &[u8]) -> Vec<u8> {
    let mut ctx = enc.to_vec();
    ctx.extend_from_slice(pk_r);
    let prk = labeled_extract(&KEM_SUITE, b"", "eae_prk", dh);
    labeled_expand(&KEM_SUITE, &prk, "shared_secret", &ctx, 32)
}

fn hpke_key_nonce(shared: &[u8], info: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut ctx = vec![0u8];
    ctx.extend_from_slice(&labeled_extract(&HPKE_SUITE, b"", "psk_id_hash", b""));
    ctx.extend_from_slice(&labeled_extract(&HPKE_SUITE, b"", "info_hash", info));
    let secret = labeled_extract(&HPKE_SUITE, shared, "secret", b"");
    (labeled_expand(&HPKE_SUITE, &secret, "key", &ctx, 16), labeled_expand(&HPKE_SUITE, &secret, "base_nonce", &ctx, 12))
}

/// SealBase with sequence number 0; `ikm_e` fixes the ephemeral key (tests).
pub fn hpke_seal(pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8], ikm_e: Option<&[u8]>) -> Res<(Vec<u8>, Vec<u8>)> {
    let _ = KEM_ID;
    let (sk_e, enc) = match ikm_e {
        Some(i) => derive_key_pair(i),
        None => generate_key_pair(),
    };
    let dh = crate::p256::ecdh(&sk_e, pk_r).ok_or("HPKE: invalid recipient public key")?;
    let (key, nonce) = hpke_key_nonce(&kem_shared(&dh, &enc, pk_r), info);
    Ok((enc, seal(&key, &nonce, aad, pt)?))
}

pub fn hpke_open(sk_r: &[u8], enc: &[u8], info: &[u8], aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
    let dh = crate::p256::ecdh(sk_r, enc).ok_or("HPKE: invalid encapsulated key")?;
    let pk_r = crate::p256::public_key(sk_r).ok_or("HPKE: invalid private key")?;
    let (key, nonce) = hpke_key_nonce(&kem_shared(&dh, enc, &pk_r), info);
    open(&key, &nonce, aad, ct)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeCt {
    pub kem: Vec<u8>,
    pub ct: Vec<u8>,
}

impl HpkeCt {
    fn enc(&self, w: &mut W) {
        w.vec(&self.kem).vec(&self.ct);
    }
    fn dec(r: &mut R) -> Res<HpkeCt> {
        Ok(HpkeCt { kem: r.vec()?.to_vec(), ct: r.vec()?.to_vec() })
    }
}

fn encrypt_context(label: &str, ctx: &[u8]) -> Vec<u8> {
    let mut w = W::default();
    w.vec(format!("MLS 1.0 {label}").as_bytes()).vec(ctx);
    w.0
}

pub fn encrypt_with_label(pk: &[u8], label: &str, ctx: &[u8], pt: &[u8]) -> Res<HpkeCt> {
    let (kem, ct) = hpke_seal(pk, &encrypt_context(label, ctx), b"", pt, None)?;
    Ok(HpkeCt { kem, ct })
}

pub fn decrypt_with_label(sk: &[u8], label: &str, ctx: &[u8], c: &HpkeCt) -> Res<Vec<u8>> {
    hpke_open(sk, &c.kem, &encrypt_context(label, ctx), b"", &c.ct)
}

// ---------------------------------------------------------------- structures

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext {
    pub typ: u16,
    pub data: Vec<u8>,
}

fn enc_exts(w: &mut W, e: &[Ext]) {
    w.nest(|w| {
        for x in e {
            w.u16(x.typ).vec(&x.data);
        }
    });
}

fn dec_exts(r: &mut R) -> Res<Vec<Ext>> {
    r.list(|r| Ok(Ext { typ: r.u16()?, data: r.vec()?.to_vec() }))
}

fn enc_u16s(w: &mut W, v: &[u16]) {
    w.nest(|w| {
        for x in v {
            w.u16(*x);
        }
    });
}

/// Credential: `kind` 1 = basic (`body` is the identity); other kinds keep their vector body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub kind: u16,
    pub body: Vec<u8>,
}

impl Credential {
    pub fn basic(identity: &[u8]) -> Credential {
        Credential { kind: 1, body: identity.to_vec() }
    }
    fn enc(&self, w: &mut W) {
        w.u16(self.kind).vec(&self.body);
    }
    fn dec(r: &mut R) -> Res<Credential> {
        Ok(Credential { kind: r.u16()?, body: r.vec()?.to_vec() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    pub versions: Vec<u16>,
    pub suites: Vec<u16>,
    pub exts: Vec<u16>,
    pub proposals: Vec<u16>,
    pub creds: Vec<u16>,
}

impl Capabilities {
    fn enc(&self, w: &mut W) {
        for v in [&self.versions, &self.suites, &self.exts, &self.proposals, &self.creds] {
            enc_u16s(w, v);
        }
    }
    fn dec(r: &mut R) -> Res<Capabilities> {
        let mut l = || r.list(|r| r.u16());
        Ok(Capabilities { versions: l()?, suites: l()?, exts: l()?, proposals: l()?, creds: l()? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    KeyPackage { not_before: u64, not_after: u64 },
    Update,
    Commit(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafNode {
    pub enc: Vec<u8>,
    pub sig_key: Vec<u8>,
    pub cred: Credential,
    pub caps: Capabilities,
    pub source: Source,
    pub exts: Vec<Ext>,
    pub sig: Vec<u8>,
}

impl LeafNode {
    fn enc_body(&self, w: &mut W) {
        w.vec(&self.enc).vec(&self.sig_key);
        self.cred.enc(w);
        self.caps.enc(w);
        match &self.source {
            Source::KeyPackage { not_before, not_after } => w.u8(1).u64(*not_before).u64(*not_after),
            Source::Update => w.u8(2),
            Source::Commit(ph) => w.u8(3).vec(ph),
        };
        enc_exts(w, &self.exts);
    }
    pub fn enc(&self, w: &mut W) {
        self.enc_body(w);
        w.vec(&self.sig);
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut w = W::default();
        self.enc(&mut w);
        w.0
    }
    pub fn dec(r: &mut R) -> Res<LeafNode> {
        let (enc, sig_key) = (r.vec()?.to_vec(), r.vec()?.to_vec());
        let cred = Credential::dec(r)?;
        let caps = Capabilities::dec(r)?;
        let source = match r.u8()? {
            1 => Source::KeyPackage { not_before: r.u64()?, not_after: r.u64()? },
            2 => Source::Update,
            3 => Source::Commit(r.vec()?.to_vec()),
            s => return err(format!("bad leaf_node_source {s}")),
        };
        Ok(LeafNode { enc, sig_key, cred, caps, source, exts: dec_exts(r)?, sig: r.vec()?.to_vec() })
    }
    /// LeafNodeTBS; update/commit leaves bind the group id and leaf index.
    fn tbs(&self, group: &[u8], index: u32) -> Vec<u8> {
        let mut w = W::default();
        self.enc_body(&mut w);
        if !matches!(self.source, Source::KeyPackage { .. }) {
            w.vec(group).u32(index);
        }
        w.0
    }
    pub fn sign(&mut self, s: &Signer, group: &[u8], index: u32) {
        self.sig = sign_with_label(s, "LeafNodeTBS", &self.tbs(group, index));
    }
    pub fn verify(&self, group: &[u8], index: u32) -> bool {
        verify_with_label(&self.sig_key, "LeafNodeTBS", &self.tbs(group, index), &self.sig)
    }
    fn parent_hash(&self) -> Option<&[u8]> {
        match &self.source {
            Source::Commit(ph) => Some(ph),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackage {
    pub init: Vec<u8>,
    pub leaf: LeafNode,
    pub exts: Vec<Ext>,
    pub sig: Vec<u8>,
}

impl KeyPackage {
    fn tbs(&self) -> Vec<u8> {
        let mut w = W::default();
        w.u16(MLS10).u16(SUITE).vec(&self.init);
        self.leaf.enc(&mut w);
        enc_exts(&mut w, &self.exts);
        w.0
    }
    pub fn new(init: Vec<u8>, leaf: LeafNode, s: &Signer) -> KeyPackage {
        let mut kp = KeyPackage { init, leaf, exts: vec![], sig: vec![] };
        kp.sig = sign_with_label(s, "KeyPackageTBS", &kp.tbs());
        kp
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut w = W::default();
        w.raw(&self.tbs()).vec(&self.sig);
        w.0
    }
    /// As an MLSMessage (what DAVE op 26 carries).
    pub fn message(&self) -> Vec<u8> {
        let mut w = W::default();
        w.u16(MLS10).u16(WF_KEY_PACKAGE).raw(&self.bytes());
        w.0
    }
    pub fn dec(r: &mut R) -> Res<KeyPackage> {
        if r.u16()? != MLS10 || r.u16()? != SUITE {
            return err("key package: unsupported version or cipher suite");
        }
        let init = r.vec()?.to_vec();
        Ok(KeyPackage { init, leaf: LeafNode::dec(r)?, exts: dec_exts(r)?, sig: r.vec()?.to_vec() })
    }
    pub fn verify(&self) -> bool {
        matches!(self.leaf.source, Source::KeyPackage { .. }) && verify_with_label(&self.leaf.sig_key, "KeyPackageTBS", &self.tbs(), &self.sig) && self.leaf.verify(&[], 0)
    }
    pub fn reference(&self) -> Vec<u8> {
        ref_hash("MLS 1.0 KeyPackage Reference", &self.bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentNode {
    pub enc: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub unmerged: Vec<u32>,
}

impl ParentNode {
    fn enc_with(&self, w: &mut W, exclude: &[u32]) {
        w.vec(&self.enc).vec(&self.parent_hash).nest(|w| {
            for l in self.unmerged.iter().filter(|l| !exclude.contains(l)) {
                w.u32(*l);
            }
        });
    }
    fn dec(r: &mut R) -> Res<ParentNode> {
        Ok(ParentNode { enc: r.vec()?.to_vec(), parent_hash: r.vec()?.to_vec(), unmerged: r.list(|r| r.u32())? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Leaf(LeafNode),
    Parent(ParentNode),
}

impl Node {
    fn public(&self) -> &[u8] {
        match self {
            Node::Leaf(l) => &l.enc,
            Node::Parent(p) => &p.enc,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskId {
    /// The encoded PreSharedKeyID.
    pub raw: Vec<u8>,
    /// External psk_id.
    pub external: Option<Vec<u8>>,
    /// Resumption PSK: (group id, epoch).
    pub resumption: Option<(Vec<u8>, u64)>,
}

impl PskId {
    fn dec(r: &mut R) -> Res<PskId> {
        let start = r.i;
        let (external, resumption) = match r.u8()? {
            1 => (Some(r.vec()?.to_vec()), None),
            2 => {
                r.u8()?;
                (None, Some((r.vec()?.to_vec(), r.u64()?)))
            }
            t => return err(format!("bad psktype {t}")),
        };
        r.vec()?;
        Ok(PskId { raw: r.since(start).to_vec(), external, resumption })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proposal {
    Add(KeyPackage),
    Update(LeafNode),
    Remove(u32),
    Psk(PskId),
    Gce(Vec<Ext>),
}

impl Proposal {
    fn enc(&self, w: &mut W) {
        match self {
            Proposal::Add(kp) => w.u16(1).raw(&kp.bytes()),
            Proposal::Update(l) => {
                w.u16(2);
                l.enc(w);
                w
            }
            Proposal::Remove(i) => w.u16(3).u32(*i),
            Proposal::Psk(p) => w.u16(4).raw(&p.raw),
            Proposal::Gce(e) => {
                w.u16(7);
                enc_exts(w, e);
                w
            }
        };
    }
    fn dec(r: &mut R) -> Res<Proposal> {
        Ok(match r.u16()? {
            1 => Proposal::Add(KeyPackage::dec(r)?),
            2 => Proposal::Update(LeafNode::dec(r)?),
            3 => Proposal::Remove(r.u32()?),
            4 => Proposal::Psk(PskId::dec(r)?),
            7 => Proposal::Gce(dec_exts(r)?),
            t => return err(format!("unsupported proposal type {t}")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalOrRef {
    Inline(Box<Proposal>),
    Ref(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePathNode {
    pub enc: Vec<u8>,
    pub secrets: Vec<HpkeCt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePath {
    pub leaf: LeafNode,
    pub nodes: Vec<UpdatePathNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}

impl Commit {
    fn enc(&self, w: &mut W) {
        w.nest(|w| {
            for p in &self.proposals {
                match p {
                    ProposalOrRef::Inline(p) => {
                        w.u8(1);
                        p.enc(w);
                    }
                    ProposalOrRef::Ref(r) => {
                        w.u8(2).vec(r);
                    }
                }
            }
        });
        match &self.path {
            None => {
                w.u8(0);
            }
            Some(p) => {
                w.u8(1);
                p.leaf.enc(w);
                w.nest(|w| {
                    for n in &p.nodes {
                        w.vec(&n.enc).nest(|w| n.secrets.iter().for_each(|c| c.enc(w)));
                    }
                });
            }
        }
    }
    fn dec(r: &mut R) -> Res<Commit> {
        let proposals = r.list(|r| match r.u8()? {
            1 => Ok(ProposalOrRef::Inline(Box::new(Proposal::dec(r)?))),
            2 => Ok(ProposalOrRef::Ref(r.vec()?.to_vec())),
            t => err(format!("bad ProposalOrRef {t}")),
        })?;
        let path = if r.optional()? {
            let leaf = LeafNode::dec(r)?;
            let nodes = r.list(|r| Ok(UpdatePathNode { enc: r.vec()?.to_vec(), secrets: r.list(HpkeCt::dec)? }))?;
            Some(UpdatePath { leaf, nodes })
        } else {
            None
        };
        Ok(Commit { proposals, path })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    Member(u32),
    External(u32),
    NewMemberProposal,
    NewMemberCommit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedContent {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub aad: Vec<u8>,
    pub content: Content,
}

impl FramedContent {
    fn enc(&self, w: &mut W) {
        w.vec(&self.group_id).u64(self.epoch);
        match self.sender {
            Sender::Member(i) => w.u8(1).u32(i),
            Sender::External(i) => w.u8(2).u32(i),
            Sender::NewMemberProposal => w.u8(3),
            Sender::NewMemberCommit => w.u8(4),
        };
        w.vec(&self.aad);
        match &self.content {
            Content::Application(d) => {
                w.u8(1).vec(d);
            }
            Content::Proposal(p) => {
                w.u8(2);
                p.enc(w);
            }
            Content::Commit(c) => {
                w.u8(3);
                c.enc(w);
            }
        }
    }
    fn dec(r: &mut R) -> Res<FramedContent> {
        let group_id = r.vec()?.to_vec();
        let epoch = r.u64()?;
        let sender = match r.u8()? {
            1 => Sender::Member(r.u32()?),
            2 => Sender::External(r.u32()?),
            3 => Sender::NewMemberProposal,
            4 => Sender::NewMemberCommit,
            t => return err(format!("bad sender type {t}")),
        };
        let aad = r.vec()?.to_vec();
        let content = match r.u8()? {
            1 => Content::Application(r.vec()?.to_vec()),
            2 => Content::Proposal(Proposal::dec(r)?),
            3 => Content::Commit(Commit::dec(r)?),
            t => return err(format!("bad content type {t}")),
        };
        Ok(FramedContent { group_id, epoch, sender, aad, content })
    }
    fn bytes(&self) -> Vec<u8> {
        let mut w = W::default();
        self.enc(&mut w);
        w.0
    }
    /// FramedContentTBS; member senders bind the GroupContext.
    fn tbs(&self, ctx: &[u8]) -> Vec<u8> {
        let mut w = W::default();
        w.u16(MLS10).u16(WF_PUBLIC).raw(&self.bytes());
        if matches!(self.sender, Sender::Member(_) | Sender::NewMemberCommit) {
            w.raw(ctx);
        }
        w.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMessage {
    pub content: FramedContent,
    pub sig: Vec<u8>,
    pub confirmation_tag: Option<Vec<u8>>,
    pub membership_tag: Option<Vec<u8>>,
}

impl PublicMessage {
    fn auth(&self) -> Vec<u8> {
        let mut w = W::default();
        w.vec(&self.sig);
        if let Some(t) = &self.confirmation_tag {
            w.vec(t);
        }
        w.0
    }
    /// AuthenticatedContent (proposal references hash this).
    fn authenticated(&self) -> Vec<u8> {
        let mut w = W::default();
        w.u16(WF_PUBLIC).raw(&self.content.bytes()).raw(&self.auth());
        w.0
    }
    pub fn message(&self) -> Vec<u8> {
        let mut w = W::default();
        w.u16(MLS10).u16(WF_PUBLIC).raw(&self.content.bytes()).raw(&self.auth());
        if let Some(t) = &self.membership_tag {
            w.vec(t);
        }
        w.0
    }
    pub fn read(r: &mut R) -> Res<PublicMessage> {
        if r.u16()? != MLS10 || r.u16()? != WF_PUBLIC {
            return err("not an MLS PublicMessage");
        }
        let content = FramedContent::dec(r)?;
        let sig = r.vec()?.to_vec();
        let confirmation_tag = if matches!(content.content, Content::Commit(_)) { Some(r.vec()?.to_vec()) } else { None };
        let membership_tag = if matches!(content.sender, Sender::Member(_)) { Some(r.vec()?.to_vec()) } else { None };
        Ok(PublicMessage { content, sig, confirmation_tag, membership_tag })
    }
    pub fn parse(b: &[u8]) -> Res<PublicMessage> {
        let mut r = R::new(b);
        let m = PublicMessage::read(&mut r)?;
        r.end()?;
        Ok(m)
    }
    /// Split concatenated PublicMessages (a DAVE proposals vector body).
    pub fn split(b: &[u8]) -> Res<Vec<Vec<u8>>> {
        let mut r = R::new(b);
        let mut out = Vec::new();
        while !r.done() {
            let start = r.i;
            PublicMessage::read(&mut r)?;
            out.push(r.since(start).to_vec());
        }
        Ok(out)
    }
    fn tbm(&self, ctx: &[u8]) -> Vec<u8> {
        let mut t = self.content.tbs(ctx);
        t.extend_from_slice(&self.auth());
        t
    }
    pub fn proposal_ref(&self) -> Vec<u8> {
        ref_hash("MLS 1.0 Proposal Reference", &self.authenticated())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupContext {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    pub cth: Vec<u8>,
    pub exts: Vec<Ext>,
}

impl GroupContext {
    pub fn bytes(&self) -> Vec<u8> {
        let mut w = W::default();
        w.u16(MLS10).u16(SUITE).vec(&self.group_id).u64(self.epoch).vec(&self.tree_hash).vec(&self.cth);
        enc_exts(&mut w, &self.exts);
        w.0
    }
    fn dec(r: &mut R) -> Res<GroupContext> {
        if r.u16()? != MLS10 || r.u16()? != SUITE {
            return err("group context: unsupported version or cipher suite");
        }
        Ok(GroupContext { group_id: r.vec()?.to_vec(), epoch: r.u64()?, tree_hash: r.vec()?.to_vec(), cth: r.vec()?.to_vec(), exts: dec_exts(r)? })
    }
}

/// An external sender (DAVE: the voice gateway) as in the external_senders extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSender {
    pub sig_key: Vec<u8>,
    pub cred: Credential,
}

impl ExternalSender {
    pub fn enc(&self, w: &mut W) {
        w.vec(&self.sig_key);
        self.cred.enc(w);
    }
    pub fn dec(r: &mut R) -> Res<ExternalSender> {
        Ok(ExternalSender { sig_key: r.vec()?.to_vec(), cred: Credential::dec(r)? })
    }
    pub fn extension(senders: &[ExternalSender]) -> Ext {
        let mut w = W::default();
        w.nest(|w| senders.iter().for_each(|s| s.enc(w)));
        Ext { typ: EXT_EXTERNAL_SENDERS, data: w.0 }
    }
    pub fn from_extensions(exts: &[Ext]) -> Res<Vec<ExternalSender>> {
        match exts.iter().find(|e| e.typ == EXT_EXTERNAL_SENDERS) {
            Some(e) => {
                let mut r = R::new(&e.data);
                let v = r.list(ExternalSender::dec)?;
                r.end()?;
                Ok(v)
            }
            None => Ok(vec![]),
        }
    }
}

// ---------------------------------------------------------------- tree

fn level(x: usize) -> u32 {
    (!x).trailing_zeros()
}

fn left(x: usize) -> usize {
    x ^ (1 << (level(x) - 1))
}

fn right(x: usize) -> usize {
    x ^ (3 << (level(x) - 1))
}

fn parent(x: usize) -> usize {
    let k = level(x);
    let b = (x >> (k + 1)) & 1;
    (x | (1 << k)) ^ (b << (k + 1))
}

fn root(n_leaves: usize) -> usize {
    let w = 2 * n_leaves - 1;
    (1 << (usize::BITS - 1 - w.leading_zeros())) - 1
}

/// Direct path of node `x` (excluding `x`, ending at the root).
fn direct_path(x: usize, n_leaves: usize) -> Vec<usize> {
    let r = root(n_leaves);
    let mut d = Vec::new();
    let mut x = x;
    while x != r {
        x = parent(x);
        d.push(x);
    }
    d
}

/// Lowest common ancestor of two nodes.
fn common_ancestor(x: usize, y: usize) -> usize {
    if x == y {
        return x;
    }
    let (mut a, mut b, mut k) = (x, y, 0);
    while a != b {
        a >>= 1;
        b >>= 1;
        k += 1;
    }
    (a << k) + (1 << (k - 1)) - 1
}

fn subtree_contains(c: usize, x: usize) -> bool {
    let h = (1usize << level(c)) - 1;
    x + h >= c && x <= c + h
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tree {
    pub nodes: Vec<Option<Node>>,
}

impl Tree {
    pub fn n_leaves(&self) -> usize {
        self.nodes.len().div_ceil(2)
    }
    pub fn leaf(&self, i: u32) -> Option<&LeafNode> {
        match self.nodes.get(2 * i as usize) {
            Some(Some(Node::Leaf(l))) => Some(l),
            _ => None,
        }
    }
    fn parent_node(&self, x: usize) -> Option<&ParentNode> {
        match self.nodes.get(x) {
            Some(Some(Node::Parent(p))) => Some(p),
            _ => None,
        }
    }
    fn parent_mut(&mut self, x: usize) -> Option<&mut ParentNode> {
        match self.nodes.get_mut(x) {
            Some(Some(Node::Parent(p))) => Some(p),
            _ => None,
        }
    }
    pub fn leaves(&self) -> impl Iterator<Item = (u32, &LeafNode)> {
        (0..self.n_leaves() as u32).filter_map(|i| self.leaf(i).map(|l| (i, l)))
    }

    /// `optional<Node> ratchet_tree<V>` (trailing blanks omitted).
    pub fn bytes(&self) -> Vec<u8> {
        let last = self.nodes.iter().rposition(Option::is_some).map_or(0, |i| i + 1);
        let mut w = W::default();
        w.nest(|w| {
            for n in &self.nodes[..last] {
                match n {
                    None => {
                        w.u8(0);
                    }
                    Some(Node::Leaf(l)) => {
                        w.u8(1).u8(1);
                        l.enc(w);
                    }
                    Some(Node::Parent(p)) => {
                        w.u8(1).u8(2);
                        p.enc_with(w, &[]);
                    }
                }
            }
        });
        w.0
    }

    pub fn parse(b: &[u8]) -> Res<Tree> {
        let mut r = R::new(b);
        let mut nodes = r.list(|r| {
            if !r.optional()? {
                return Ok(None);
            }
            Ok(Some(match r.u8()? {
                1 => Node::Leaf(LeafNode::dec(r)?),
                2 => Node::Parent(ParentNode::dec(r)?),
                t => return err(format!("bad node type {t}")),
            }))
        })?;
        r.end()?;
        if nodes.last().is_none_or(Option::is_none) {
            return err("ratchet tree empty or ends with a blank node");
        }
        let mut w = 1;
        while w < nodes.len() {
            w = 2 * w + 1;
        }
        nodes.resize(w, None);
        for (i, n) in nodes.iter().enumerate() {
            if matches!((i % 2, n), (0, Some(Node::Parent(_))) | (1, Some(Node::Leaf(_)))) {
                return err("ratchet tree node of the wrong type");
            }
        }
        Ok(Tree { nodes })
    }

    pub fn resolution(&self, x: usize) -> Vec<usize> {
        match &self.nodes[x] {
            Some(Node::Leaf(_)) => vec![x],
            Some(Node::Parent(p)) => std::iter::once(x).chain(p.unmerged.iter().map(|l| 2 * *l as usize)).collect(),
            None if x.is_multiple_of(2) => vec![],
            None => [self.resolution(left(x)), self.resolution(right(x))].concat(),
        }
    }

    /// (parent, copath child) for every node of the filtered direct path of leaf `i`.
    pub fn filtered_path(&self, i: u32) -> Vec<(usize, usize)> {
        let mut prev = 2 * i as usize;
        let mut out = Vec::new();
        for p in direct_path(prev, self.n_leaves()) {
            let c = if prev < p { right(p) } else { left(p) };
            if !self.resolution(c).is_empty() {
                out.push((p, c));
            }
            prev = p;
        }
        out
    }

    pub fn hash(&self, x: usize, exclude: &[u32]) -> [u8; 32] {
        let mut w = W::default();
        if x.is_multiple_of(2) {
            let idx = (x / 2) as u32;
            w.u8(1).u32(idx);
            match &self.nodes[x] {
                Some(Node::Leaf(l)) if !exclude.contains(&idx) => {
                    w.u8(1);
                    l.enc(&mut w);
                }
                _ => {
                    w.u8(0);
                }
            }
        } else {
            w.u8(2);
            match &self.nodes[x] {
                Some(Node::Parent(p)) => {
                    w.u8(1);
                    p.enc_with(&mut w, exclude);
                }
                _ => {
                    w.u8(0);
                }
            }
            w.vec(&self.hash(left(x), exclude)).vec(&self.hash(right(x), exclude));
        }
        hash(&w.0)
    }

    pub fn root_hash(&self) -> Vec<u8> {
        self.hash(root(self.n_leaves()), &[]).to_vec()
    }

    /// Parent hash of `p` with copath child `s`.
    fn parent_hash_of(&self, p: usize, s: usize) -> Vec<u8> {
        let pn = self.parent_node(p).expect("parent hash of a blank node");
        let mut w = W::default();
        w.vec(&pn.enc).vec(&pn.parent_hash).vec(&self.hash(s, &pn.unmerged));
        hash(&w.0).to_vec()
    }

    fn node_parent_hash(&self, x: usize) -> Option<&[u8]> {
        match &self.nodes[x] {
            Some(Node::Leaf(l)) => l.parent_hash(),
            Some(Node::Parent(p)) => Some(&p.parent_hash),
            None => None,
        }
    }

    /// RFC 9420 §7.9.2, top down: every non-blank parent has exactly one descendant whose
    /// parent hash chains to it.
    pub fn parent_hashes_valid(&self) -> bool {
        (0..self.nodes.len()).filter(|x| x % 2 == 1).all(|p| {
            let Some(pn) = self.parent_node(p) else { return true };
            let mut found = 0;
            for (c, s) in [(left(p), right(p)), (right(p), left(p))] {
                let ph = self.parent_hash_of(p, s);
                let res = self.resolution(c);
                let mut unmerged: Vec<usize> = pn.unmerged.iter().map(|l| 2 * *l as usize).filter(|x| subtree_contains(c, *x)).collect();
                unmerged.sort();
                for d in &res {
                    if self.node_parent_hash(*d) != Some(&ph[..]) {
                        continue;
                    }
                    let mut rest: Vec<usize> = res.iter().copied().filter(|x| x != d).collect();
                    rest.sort();
                    if rest == unmerged {
                        found += 1;
                    }
                }
            }
            found == 1
        })
    }

    fn blank_path(&mut self, i: u32) {
        for p in direct_path(2 * i as usize, self.n_leaves()) {
            self.nodes[p] = None;
        }
    }

    pub fn add(&mut self, leaf: LeafNode) -> u32 {
        let i = match (0..self.n_leaves() as u32).find(|i| self.nodes[2 * *i as usize].is_none()) {
            Some(i) => i,
            None => {
                let n = self.n_leaves() as u32;
                let len = self.nodes.len();
                self.nodes.resize(2 * len + 1, None);
                n
            }
        };
        self.nodes[2 * i as usize] = Some(Node::Leaf(leaf));
        for p in direct_path(2 * i as usize, self.n_leaves()) {
            if let Some(pn) = self.parent_mut(p) {
                pn.unmerged.push(i);
            }
        }
        i
    }

    pub fn remove(&mut self, i: u32) -> Res<()> {
        if self.leaf(i).is_none() {
            return err(format!("remove: leaf {i} is blank"));
        }
        self.nodes[2 * i as usize] = None;
        self.blank_path(i);
        while self.nodes.len() > 1 && self.nodes[self.nodes.len().div_ceil(2)..].iter().step_by(2).all(Option::is_none) {
            let len = self.nodes.len();
            self.nodes.truncate((len - 1) / 2);
        }
        Ok(())
    }

    fn update(&mut self, i: u32, leaf: LeafNode) {
        self.nodes[2 * i as usize] = Some(Node::Leaf(leaf));
        self.blank_path(i);
    }

    /// Set the new public keys along leaf `i`'s filtered direct path and return the
    /// parent hash its new leaf must carry (computed root to leaf).
    fn merge_path(&mut self, i: u32, path: &[(usize, usize)], keys: &[Vec<u8>]) -> Vec<u8> {
        self.blank_path(i);
        for ((p, _), k) in path.iter().zip(keys) {
            self.nodes[*p] = Some(Node::Parent(ParentNode { enc: k.clone(), parent_hash: vec![], unmerged: vec![] }));
        }
        let mut next = Vec::new();
        for (p, s) in path.iter().rev() {
            self.parent_mut(*p).unwrap().parent_hash = next;
            next = self.parent_hash_of(*p, *s);
        }
        next
    }

    fn find_public(&self, pk: &[u8]) -> bool {
        self.nodes.iter().flatten().any(|n| n.public() == pk)
    }
}

// ---------------------------------------------------------------- group state

#[derive(Clone)]
struct Epoch {
    init: Vec<u8>,
    exporter: Vec<u8>,
    confirm: Vec<u8>,
    membership: Vec<u8>,
    authenticator: Vec<u8>,
    resumption: Vec<u8>,
}

impl Epoch {
    fn from_secret(es: &[u8]) -> Epoch {
        Epoch {
            init: derive_secret(es, "init"),
            exporter: derive_secret(es, "exporter"),
            confirm: derive_secret(es, "confirm"),
            membership: derive_secret(es, "membership"),
            authenticator: derive_secret(es, "authentication"),
            resumption: derive_secret(es, "resumption"),
        }
    }
}

/// psk_secret over the given PSK ids; `lookup` resolves external psk ids, `resumption`
/// holds (group id, epoch) → resumption_psk of epochs we were in.
fn psk_secret(ids: &[&PskId], lookup: &dyn Fn(&[u8]) -> Option<Vec<u8>>, resumption: &[(Vec<u8>, u64, Vec<u8>)]) -> Res<Vec<u8>> {
    let mut acc = vec![0u8; NH];
    for (i, id) in ids.iter().enumerate() {
        let psk = match (&id.external, &id.resumption) {
            (Some(e), _) => lookup(e),
            (_, Some((g, ep))) => resumption.iter().find(|(gg, ee, _)| gg == g && ee == ep).map(|(_, _, p)| p.clone()),
            _ => None,
        }
        .ok_or("PSK not available")?;
        let mut label = W::default();
        label.raw(&id.raw).u16(i as u16).u16(ids.len() as u16);
        let input = expand_with_label(&extract(&[0u8; NH], &psk), "derived psk", &label.0, NH);
        acc = extract(&input, &acc).to_vec();
    }
    Ok(acc)
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_sha256(key, data).to_vec()
}

fn interim(cth: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut w = W::default();
    w.raw(cth).vec(tag);
    hash(&w.0).to_vec()
}

/// A proposal received in the current epoch, kept until a commit references it.
#[derive(Debug, Clone)]
pub struct Cached {
    pub reference: Vec<u8>,
    pub proposal: Proposal,
    pub sender: Sender,
}

pub type PskLookup<'a> = &'a dyn Fn(&[u8]) -> Option<Vec<u8>>;

pub fn no_psks(_: &[u8]) -> Option<Vec<u8>> {
    None
}

/// One member's view of an MLS group in one epoch.
#[derive(Clone)]
pub struct Group {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree: Tree,
    pub cth: Vec<u8>,
    interim: Vec<u8>,
    pub exts: Vec<Ext>,
    pub me: u32,
    /// HPKE private keys for our leaf and the parent nodes we hold.
    privs: BTreeMap<usize, [u8; 32]>,
    pub signer: Arc<Signer>,
    secrets: Epoch,
    /// resumption_psk of recent epochs: (group id, epoch, psk).
    history: Vec<(Vec<u8>, u64, Vec<u8>)>,
}

/// The outcome of creating a commit: the MLSMessage, the bare Welcome (if members were added)
/// and the state to switch to if the delivery service accepts it.
pub struct Outgoing {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub next: Group,
}

struct Applied {
    tree: Tree,
    exts: Vec<Ext>,
    added: Vec<(u32, KeyPackage)>,
    psks: Vec<PskId>,
    path_required: bool,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Group(epoch {}, leaf {}, {} members)", self.epoch, self.me, self.tree.leaves().count())
    }
}

impl Group {
    /// A one-member group at epoch 0 (RFC 9420 §11).
    pub fn create(group_id: &[u8], leaf: LeafNode, leaf_priv: [u8; 32], signer: Arc<Signer>, exts: Vec<Ext>) -> Group {
        let tree = Tree { nodes: vec![Some(Node::Leaf(leaf))] };
        let secrets = Epoch::from_secret(&random_bytes(NH));
        let tag = mac(&secrets.confirm, &[]);
        let history = vec![(group_id.to_vec(), 0, secrets.resumption.clone())];
        Group { group_id: group_id.to_vec(), epoch: 0, tree, cth: vec![], interim: interim(&[], &tag), exts, me: 0, privs: BTreeMap::from([(0, leaf_priv)]), signer, secrets, history }
    }

    pub fn context(&self) -> GroupContext {
        GroupContext { group_id: self.group_id.clone(), epoch: self.epoch, tree_hash: self.tree.root_hash(), cth: self.cth.clone(), exts: self.exts.clone() }
    }

    pub fn epoch_authenticator(&self) -> &[u8] {
        &self.secrets.authenticator
    }

    /// MLS-Exporter (RFC 9420 §8.5).
    pub fn export(&self, label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
        expand_with_label(&derive_secret(&self.secrets.exporter, label), "exported", &hash(ctx), len)
    }

    pub fn members(&self) -> impl Iterator<Item = (u32, &LeafNode)> {
        self.tree.leaves()
    }

    /// Verify a PublicMessage (signature, and membership tag for members) of this epoch.
    pub fn unwrap(&self, msg: &[u8]) -> Res<PublicMessage> {
        let m = PublicMessage::parse(msg)?;
        if m.content.group_id != self.group_id {
            return err("message for another group");
        }
        if m.content.epoch != self.epoch {
            return err(format!("message for epoch {} (current {})", m.content.epoch, self.epoch));
        }
        let ctx = self.context().bytes();
        let key = match m.content.sender {
            Sender::Member(i) => {
                let expected = mac(&self.secrets.membership, &m.tbm(&ctx));
                if !m.membership_tag.as_ref().is_some_and(|t| seagent_net::crypto::ct_eq(t, &expected)) {
                    return err("bad membership tag");
                }
                self.tree.leaf(i).ok_or("sender leaf is blank")?.sig_key.clone()
            }
            Sender::External(i) => {
                if !matches!(m.content.content, Content::Proposal(Proposal::Add(_) | Proposal::Remove(_))) {
                    return err("external senders may only propose add/remove");
                }
                ExternalSender::from_extensions(&self.exts)?.get(i as usize).ok_or("unknown external sender")?.sig_key.clone()
            }
            _ => return err("new-member senders are not supported"),
        };
        if !verify_with_label(&key, "FramedContentTBS", &m.content.tbs(&ctx), &m.sig) {
            return err("bad signature on MLS message");
        }
        Ok(m)
    }

    /// A proposal message → its cached form with the proposal reference.
    pub fn proposal(&self, msg: &[u8]) -> Res<Cached> {
        let m = self.unwrap(msg)?;
        let Content::Proposal(p) = &m.content.content else { return err("not a proposal") };
        Ok(Cached { reference: m.proposal_ref(), proposal: p.clone(), sender: m.content.sender })
    }

    fn apply(&self, props: &[(Proposal, Sender)]) -> Res<Applied> {
        let mut tree = self.tree.clone();
        let mut exts = self.exts.clone();
        let mut path_required = props.is_empty();
        for (p, _) in props {
            if let Proposal::Gce(e) = p {
                exts = e.clone();
                path_required = true;
            }
        }
        for (p, s) in props {
            if let Proposal::Update(l) = p {
                let Sender::Member(i) = s else { return err("update from a non-member") };
                if !l.verify(&self.group_id, *i) || l.source != Source::Update {
                    return err("invalid update leaf node");
                }
                tree.update(*i, l.clone());
                path_required = true;
            }
        }
        for (p, _) in props {
            if let Proposal::Remove(i) = p {
                tree.remove(*i)?;
                path_required = true;
            }
        }
        let mut added = Vec::new();
        for (p, _) in props {
            if let Proposal::Add(kp) = p {
                if !kp.verify() {
                    return err("add proposal with an invalid key package");
                }
                added.push((tree.add(kp.leaf.clone()), kp.clone()));
            }
        }
        let psks = props.iter().filter_map(|(p, _)| if let Proposal::Psk(id) = p { Some(id.clone()) } else { None }).collect();
        Ok(Applied { tree, exts, added, psks, path_required })
    }

    fn resolve(&self, c: &Commit, committer: u32, cache: &[Cached]) -> Res<Vec<(Proposal, Sender)>> {
        c.proposals
            .iter()
            .map(|p| match p {
                ProposalOrRef::Inline(p) => Ok(((**p).clone(), Sender::Member(committer))),
                ProposalOrRef::Ref(r) => cache.iter().find(|c| &c.reference == r).map(|c| (c.proposal.clone(), c.sender)).ok_or_else(|| "commit references an unknown proposal".to_string()),
            })
            .collect()
    }

    fn next_history(&self, next: &Epoch) -> Vec<(Vec<u8>, u64, Vec<u8>)> {
        let mut h = self.history.clone();
        h.push((self.group_id.clone(), self.epoch + 1, next.resumption.clone()));
        let n = h.len();
        h.split_off(n.saturating_sub(8))
    }

    /// Key schedule from the previous init secret; returns (joiner, member secret, epoch).
    fn schedule(&self, commit_secret: &[u8], psk: &[u8], ctx: &[u8]) -> (Vec<u8>, [u8; 32], Epoch) {
        let joiner = expand_with_label(&extract(&self.secrets.init, commit_secret), "joiner", ctx, NH);
        let member = extract(&joiner, psk);
        let es = expand_with_label(&member, "epoch", ctx, NH);
        (joiner, member, Epoch::from_secret(&es))
    }

    /// Process a Commit (PublicMessage) from another member; returns the next epoch's state.
    pub fn process_commit(&self, msg: &[u8], cache: &[Cached], psks: PskLookup) -> Res<Group> {
        let m = self.unwrap(msg)?;
        let Sender::Member(committer) = m.content.sender else { return err("commit from a non-member") };
        if committer == self.me {
            return err("cannot process our own commit; use the state cached when creating it");
        }
        let Content::Commit(c) = &m.content.content else { return err("not a commit") };
        let props = self.resolve(c, committer, cache)?;
        let mut a = self.apply(&props)?;
        if a.path_required && c.path.is_none() {
            return err("commit needs an update path");
        }
        if props.iter().any(|(p, _)| matches!(p, Proposal::Remove(i) if *i == self.me)) {
            return err("removed from the group");
        }
        let mut privs: BTreeMap<usize, [u8; 32]> = self.privs.iter().filter(|(x, _)| a.tree.nodes.get(**x).is_some_and(Option::is_some)).map(|(k, v)| (*k, *v)).collect();
        let mut commit_secret = vec![0u8; NH];
        if let Some(path) = &c.path {
            let fp = a.tree.filtered_path(committer);
            if fp.len() != path.nodes.len() {
                return err("update path length does not match the filtered direct path");
            }
            if !matches!(path.leaf.source, Source::Commit(_)) || !path.leaf.verify(&self.group_id, committer) {
                return err("invalid committer leaf node");
            }
            if self.tree.leaf(committer).is_some_and(|l| l.enc == path.leaf.enc) {
                return err("committer reused its encryption key");
            }
            for k in std::iter::once(&path.leaf.enc).chain(path.nodes.iter().map(|n| &n.enc)) {
                if a.tree.find_public(k) && self.tree.leaf(committer).is_none_or(|l| &l.enc != k) {
                    return err("update path reuses a public key from the tree");
                }
            }
            let keys: Vec<Vec<u8>> = path.nodes.iter().map(|n| n.enc.clone()).collect();
            let ph = a.tree.merge_path(committer, &fp, &keys);
            if path.leaf.parent_hash() != Some(&ph[..]) {
                return err("committer leaf parent hash mismatch");
            }
            a.tree.nodes[2 * committer as usize] = Some(Node::Leaf(path.leaf.clone()));
            for x in direct_path(2 * committer as usize, a.tree.n_leaves()) {
                privs.remove(&x);
            }
            let provisional = GroupContext { group_id: self.group_id.clone(), epoch: self.epoch + 1, tree_hash: a.tree.root_hash(), cth: self.cth.clone(), exts: a.exts.clone() }.bytes();
            // The lowest node of the path above us; decrypt with a key from its copath resolution.
            let mine = 2 * self.me as usize;
            let k = fp.iter().position(|(_, c)| subtree_contains(*c, mine)).ok_or("no update path node above us")?;
            let new_leaves: Vec<usize> = a.added.iter().map(|(i, _)| 2 * *i as usize).collect();
            let res: Vec<usize> = a.tree.resolution(fp[k].1).into_iter().filter(|x| !new_leaves.contains(x)).collect();
            if res.len() != path.nodes[k].secrets.len() {
                return err("update path ciphertext count mismatch");
            }
            let (pos, sk) = res.iter().enumerate().find_map(|(j, x)| privs.get(x).map(|sk| (j, *sk))).ok_or("no private key for the update path")?;
            let mut secret = decrypt_with_label(&sk, "UpdatePathNode", &provisional, &path.nodes[k].secrets[pos])?;
            for (j, (p, _)) in fp.iter().enumerate().skip(k) {
                if j > k {
                    secret = derive_secret(&secret, "path");
                }
                let (sk, pk) = derive_key_pair(&derive_secret(&secret, "node"));
                if pk != path.nodes[j].enc {
                    return err("derived path key does not match the update path");
                }
                privs.insert(*p, sk);
            }
            commit_secret = derive_secret(&secret, "path");
        }
        let psk_ids: Vec<&PskId> = a.psks.iter().collect();
        let psk = psk_secret(&psk_ids, psks, &self.history)?;
        let mut cth_in = W::default();
        cth_in.raw(&self.interim).u16(WF_PUBLIC).raw(&m.content.bytes()).vec(&m.sig);
        let cth = hash(&cth_in.0).to_vec();
        let ctx = GroupContext { group_id: self.group_id.clone(), epoch: self.epoch + 1, tree_hash: a.tree.root_hash(), cth: cth.clone(), exts: a.exts.clone() };
        let (_, _, secrets) = self.schedule(&commit_secret, &psk, &ctx.bytes());
        let tag = m.confirmation_tag.clone().unwrap_or_default();
        if !seagent_net::crypto::ct_eq(&tag, &mac(&secrets.confirm, &cth)) {
            return err("bad confirmation tag");
        }
        let history = self.next_history(&secrets);
        Ok(Group { group_id: self.group_id.clone(), epoch: self.epoch + 1, tree: a.tree, interim: interim(&cth, &tag), cth, exts: a.exts, me: self.me, privs, signer: self.signer.clone(), secrets, history })
    }

    /// Commit the given cached proposals (by reference), with an UpdatePath when required or `force_path`.
    pub fn commit(&self, cache: &[Cached], force_path: bool) -> Res<Outgoing> {
        let props: Vec<(Proposal, Sender)> = cache.iter().map(|c| (c.proposal.clone(), c.sender)).collect();
        if props.iter().any(|(p, _)| matches!(p, Proposal::Remove(i) if *i == self.me)) {
            return err("cannot commit our own removal");
        }
        let mut a = self.apply(&props)?;
        let mut privs: BTreeMap<usize, [u8; 32]> = self.privs.iter().filter(|(x, _)| a.tree.nodes.get(**x).is_some_and(Option::is_some)).map(|(k, v)| (*k, *v)).collect();
        let mut commit_secret = vec![0u8; NH];
        let mut path = None;
        let mut path_secrets: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        if a.path_required || force_path {
            let fp = a.tree.filtered_path(self.me);
            let leaf_secret = random_bytes(NH);
            let (leaf_sk, leaf_pk) = derive_key_pair(&derive_secret(&leaf_secret, "node"));
            let mut secret = derive_secret(&leaf_secret, "path");
            let mut keys = Vec::new();
            for (j, (p, _)) in fp.iter().enumerate() {
                if j > 0 {
                    secret = derive_secret(&secret, "path");
                }
                let (sk, pk) = derive_key_pair(&derive_secret(&secret, "node"));
                privs.insert(*p, sk);
                path_secrets.insert(*p, secret.clone());
                keys.push(pk);
            }
            commit_secret = if fp.is_empty() { secret } else { derive_secret(&secret, "path") };
            for x in direct_path(2 * self.me as usize, a.tree.n_leaves()) {
                if !path_secrets.contains_key(&x) {
                    privs.remove(&x);
                }
            }
            let ph = a.tree.merge_path(self.me, &fp, &keys);
            let mut leaf = a.tree.leaf(self.me).ok_or("our leaf is blank")?.clone();
            leaf.enc = leaf_pk;
            leaf.source = Source::Commit(ph);
            leaf.sign(&self.signer, &self.group_id, self.me);
            a.tree.nodes[2 * self.me as usize] = Some(Node::Leaf(leaf.clone()));
            privs.insert(2 * self.me as usize, leaf_sk);
            let provisional = GroupContext { group_id: self.group_id.clone(), epoch: self.epoch + 1, tree_hash: a.tree.root_hash(), cth: self.cth.clone(), exts: a.exts.clone() }.bytes();
            let new_leaves: Vec<usize> = a.added.iter().map(|(i, _)| 2 * *i as usize).collect();
            let mut nodes = Vec::new();
            for ((p, c), pk) in fp.iter().zip(keys) {
                let secret = &path_secrets[p];
                let secrets = a.tree.resolution(*c).into_iter().filter(|x| !new_leaves.contains(x)).map(|x| encrypt_with_label(a.tree.nodes[x].as_ref().unwrap().public(), "UpdatePathNode", &provisional, secret)).collect::<Res<Vec<_>>>()?;
                nodes.push(UpdatePathNode { enc: pk, secrets });
            }
            path = Some(UpdatePath { leaf, nodes });
        }
        let commit = Commit { proposals: cache.iter().map(|c| ProposalOrRef::Ref(c.reference.clone())).collect(), path };
        let content = FramedContent { group_id: self.group_id.clone(), epoch: self.epoch, sender: Sender::Member(self.me), aad: vec![], content: Content::Commit(commit) };
        let old_ctx = self.context().bytes();
        let sig = sign_with_label(&self.signer, "FramedContentTBS", &content.tbs(&old_ctx));
        let mut cth_in = W::default();
        cth_in.raw(&self.interim).u16(WF_PUBLIC).raw(&content.bytes()).vec(&sig);
        let cth = hash(&cth_in.0).to_vec();
        let ctx = GroupContext { group_id: self.group_id.clone(), epoch: self.epoch + 1, tree_hash: a.tree.root_hash(), cth: cth.clone(), exts: a.exts.clone() };
        let ctx_bytes = ctx.bytes();
        let psk_ids: Vec<&PskId> = a.psks.iter().collect();
        if !psk_ids.is_empty() {
            return err("committing PSK proposals is not supported");
        }
        let (joiner, member, secrets) = self.schedule(&commit_secret, &[0u8; NH], &ctx_bytes);
        let tag = mac(&secrets.confirm, &cth);
        let mut msg = PublicMessage { content, sig, confirmation_tag: Some(tag.clone()), membership_tag: None };
        msg.membership_tag = Some(mac(&self.secrets.membership, &msg.tbm(&old_ctx)));
        let history = self.next_history(&secrets);
        let next = Group { group_id: self.group_id.clone(), epoch: self.epoch + 1, tree: a.tree.clone(), interim: interim(&cth, &tag), cth, exts: a.exts.clone(), me: self.me, privs, signer: self.signer.clone(), secrets, history };
        let welcome = if a.added.is_empty() {
            None
        } else {
            let mut gi = W::default();
            gi.raw(&ctx_bytes);
            enc_exts(&mut gi, &[Ext { typ: EXT_RATCHET_TREE, data: a.tree.bytes() }]);
            gi.vec(&tag).u32(self.me);
            let gsig = sign_with_label(&self.signer, "GroupInfoTBS", &gi.0);
            gi.vec(&gsig);
            let welcome_secret = derive_secret(&member, "welcome");
            let egi = seal(&expand_with_label(&welcome_secret, "key", &[], 16), &expand_with_label(&welcome_secret, "nonce", &[], 12), &[], &gi.0)?;
            let mut w = W::default();
            w.u16(SUITE);
            let mut secrets_vec = W::default();
            for (i, kp) in &a.added {
                let mut gs = W::default();
                gs.vec(&joiner);
                match path_secrets.get(&common_ancestor(2 * self.me as usize, 2 * *i as usize)) {
                    Some(s) => gs.u8(1).vec(s),
                    None => gs.u8(0),
                };
                gs.vec(&[]);
                secrets_vec.vec(&kp.reference());
                encrypt_with_label(&kp.init, "Welcome", &egi, &gs.0)?.enc(&mut secrets_vec);
            }
            w.vec(&secrets_vec.0).vec(&egi);
            Some(w.0)
        };
        Ok(Outgoing { commit: msg.message(), welcome, next })
    }

    /// Join from a Welcome (bare `Welcome` or an MLSMessage wrapping one).
    pub fn join(welcome: &[u8], kp: &KeyPackage, init_priv: &[u8; 32], leaf_priv: [u8; 32], signer: Arc<Signer>, tree: Option<Tree>, psks: PskLookup) -> Res<Group> {
        let mut r = R::new(welcome);
        if welcome.len() > 4 && welcome[..4] == [0, 1, 0, 3] {
            r.u16()?;
            r.u16()?;
        }
        if r.u16()? != SUITE {
            return err("welcome: unsupported cipher suite");
        }
        let my_ref = kp.reference();
        let secrets = r.list(|r| Ok((r.vec()?.to_vec(), HpkeCt::dec(r)?)))?;
        let egi = r.vec()?.to_vec();
        r.end()?;
        let (_, ct) = secrets.iter().find(|(k, _)| *k == my_ref).ok_or("welcome is not for our key package")?;
        let gs = decrypt_with_label(init_priv, "Welcome", &egi, ct)?;
        let mut g = R::new(&gs);
        let joiner = g.vec()?.to_vec();
        let path_secret = if g.optional()? { Some(g.vec()?.to_vec()) } else { None };
        let psk_ids = g.list(PskId::dec)?;
        g.end()?;
        let psk = psk_secret(&psk_ids.iter().collect::<Vec<_>>(), psks, &[])?;
        let member = extract(&joiner, &psk);
        let welcome_secret = derive_secret(&member, "welcome");
        let gi = open(&expand_with_label(&welcome_secret, "key", &[], 16), &expand_with_label(&welcome_secret, "nonce", &[], 12), &[], &egi)?;
        let mut r = R::new(&gi);
        let ctx = GroupContext::dec(&mut r)?;
        let gexts = dec_exts(&mut r)?;
        let tag = r.vec()?.to_vec();
        let signer_idx = r.u32()?;
        let tbs_len = r.i;
        let gsig = r.vec()?.to_vec();
        r.end()?;
        let tree = match gexts.iter().find(|e| e.typ == EXT_RATCHET_TREE) {
            Some(e) => Tree::parse(&e.data)?,
            None => tree.ok_or("welcome without a ratchet tree")?,
        };
        if tree.root_hash() != ctx.tree_hash {
            return err("ratchet tree does not match the tree hash");
        }
        let gsigner = tree.leaf(signer_idx).ok_or("group info signer is blank")?;
        if !verify_with_label(&gsigner.sig_key, "GroupInfoTBS", &gi[..tbs_len], &gsig) {
            return err("bad group info signature");
        }
        for (i, l) in tree.leaves() {
            if !l.verify(&ctx.group_id, i) {
                return err(format!("leaf {i} has an invalid signature"));
            }
        }
        if !tree.parent_hashes_valid() {
            return err("ratchet tree parent hashes are invalid");
        }
        let me = tree.leaves().find(|(_, l)| **l == kp.leaf).map(|(i, _)| i).ok_or("our leaf is not in the tree")?;
        let mut privs = BTreeMap::from([(2 * me as usize, leaf_priv)]);
        if let Some(mut secret) = path_secret {
            let lca = common_ancestor(2 * me as usize, 2 * signer_idx as usize);
            let fp = tree.filtered_path(signer_idx);
            let k = fp.iter().position(|(p, _)| *p == lca).ok_or("path secret for a node not on the committer's path")?;
            for (j, (p, _)) in fp.iter().enumerate().skip(k) {
                if j > k {
                    secret = derive_secret(&secret, "path");
                }
                let (sk, pk) = derive_key_pair(&derive_secret(&secret, "node"));
                if tree.parent_node(*p).map(|n| &n.enc) != Some(&pk) {
                    return err("welcome path secret does not match the tree");
                }
                privs.insert(*p, sk);
            }
        }
        let secrets = Epoch::from_secret(&expand_with_label(&member, "epoch", &ctx.bytes(), NH));
        if !seagent_net::crypto::ct_eq(&tag, &mac(&secrets.confirm, &ctx.cth)) {
            return err("bad confirmation tag in group info");
        }
        let history = vec![(ctx.group_id.clone(), ctx.epoch, secrets.resumption.clone())];
        Ok(Group { group_id: ctx.group_id, epoch: ctx.epoch, tree, interim: interim(&ctx.cth, &tag), cth: ctx.cth, exts: ctx.exts, me, privs, signer, secrets, history })
    }
}

/// An external sender's signed proposal (what the DAVE voice gateway broadcasts).
pub fn external_proposal(signer: &Signer, sender_index: u32, group_id: &[u8], epoch: u64, proposal: Proposal) -> Vec<u8> {
    let content = FramedContent { group_id: group_id.to_vec(), epoch, sender: Sender::External(sender_index), aad: vec![], content: Content::Proposal(proposal) };
    let sig = sign_with_label(signer, "FramedContentTBS", &content.tbs(&[]));
    PublicMessage { content, sig, confirmation_tag: None, membership_tag: None }.message()
}

/// A fresh leaf node for a key package: (leaf, HPKE private key).
pub fn new_leaf(identity: &[u8], signer: &Signer) -> (LeafNode, [u8; 32]) {
    let (sk, pk) = generate_key_pair();
    let caps = Capabilities { versions: vec![MLS10], suites: vec![SUITE], exts: vec![], proposals: vec![], creds: vec![1] };
    let mut leaf = LeafNode { enc: pk, sig_key: signer.public(), cred: Credential::basic(identity), caps, source: Source::KeyPackage { not_before: 0, not_after: u64::MAX }, exts: vec![], sig: vec![] };
    leaf.sign(signer, &[], 0);
    (leaf, sk)
}

/// Strip the MLSMessage header of a KeyPackage message.
pub fn parse_key_package(msg: &[u8]) -> Res<KeyPackage> {
    let mut r = R::new(msg);
    if r.u16()? != MLS10 || r.u16()? != WF_KEY_PACKAGE {
        return err("not an MLS KeyPackage message");
    }
    let kp = KeyPackage::dec(&mut r)?;
    r.end()?;
    Ok(kp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_net::crypto::{hex, hex_decode};
    use serde_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        hex_decode(v.as_str().unwrap_or("")).unwrap()
    }

    fn vectors(name: &str) -> Vec<Value> {
        let all: Vec<Value> = serde_json::from_str(match name {
            "crypto-basics" => include_str!("testdata/mls/crypto-basics.json"),
            "key-schedule" => include_str!("testdata/mls/key-schedule.json"),
            "transcript-hashes" => include_str!("testdata/mls/transcript-hashes.json"),
            "welcome" => include_str!("testdata/mls/welcome.json"),
            "tree-math" => include_str!("testdata/mls/tree-math.json"),
            "tree-validation" => include_str!("testdata/mls/tree-validation.json"),
            "passive-client-welcome" => include_str!("testdata/mls/passive-client-welcome.json"),
            "passive-client-handling-commit" => include_str!("testdata/mls/passive-client-handling-commit.json"),
            _ => unreachable!(),
        })
        .unwrap();
        all.into_iter().filter(|v| v["cipher_suite"].as_u64().is_none_or(|c| c == 2)).collect()
    }

    #[test]
    fn hpke_rfc9180_p256_vector() {
        let (sk_r, pk_r) = derive_key_pair(&h(&"668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550".into()));
        assert_eq!(hex(&sk_r), "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        let info = h(&"4f6465206f6e2061204772656369616e2055726e".into());
        let pt = h(&"4265617574792069732074727574682c20747275746820626561757479".into());
        let ikm_e = h(&"4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e".into());
        let (enc, ct) = hpke_seal(&pk_r, &info, b"Count-0", &pt, Some(&ikm_e)).unwrap();
        assert_eq!(hex(&enc), "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
        assert_eq!(hex(&ct), "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434");
        assert_eq!(hpke_open(&sk_r, &enc, &info, b"Count-0", &ct).unwrap(), pt);
        assert!(hpke_open(&sk_r, &enc, &info, b"Count-1", &ct).is_err());
    }

    #[test]
    fn crypto_basics_vectors() {
        for v in vectors("crypto-basics") {
            let r = &v["ref_hash"];
            assert_eq!(ref_hash(r["label"].as_str().unwrap(), &h(&r["value"])), h(&r["out"]));
            let e = &v["expand_with_label"];
            assert_eq!(expand_with_label(&h(&e["secret"]), e["label"].as_str().unwrap(), &h(&e["context"]), e["length"].as_u64().unwrap() as usize), h(&e["out"]));
            let d = &v["derive_secret"];
            assert_eq!(derive_secret(&h(&d["secret"]), d["label"].as_str().unwrap()), h(&d["out"]));
            let t = &v["derive_tree_secret"];
            assert_eq!(derive_tree_secret(&h(&t["secret"]), t["label"].as_str().unwrap(), t["generation"].as_u64().unwrap() as u32, t["length"].as_u64().unwrap() as usize), h(&t["out"]));
            let s = &v["sign_with_label"];
            assert!(verify_with_label(&h(&s["pub"]), s["label"].as_str().unwrap(), &h(&s["content"]), &h(&s["signature"])));
            let signer = Signer::from_scalar(&h(&s["priv"])).unwrap();
            assert_eq!(signer.public(), h(&s["pub"]));
            let mine = sign_with_label(&signer, s["label"].as_str().unwrap(), &h(&s["content"]));
            assert!(verify_with_label(&h(&s["pub"]), s["label"].as_str().unwrap(), &h(&s["content"]), &mine));
            let c = &v["encrypt_with_label"];
            let ct = HpkeCt { kem: h(&c["kem_output"]), ct: h(&c["ciphertext"]) };
            let (label, ctx) = (c["label"].as_str().unwrap(), h(&c["context"]));
            assert_eq!(decrypt_with_label(&h(&c["priv"]), label, &ctx, &ct).unwrap(), h(&c["plaintext"]));
            let again = encrypt_with_label(&h(&c["pub"]), label, &ctx, b"round trip").unwrap();
            assert_eq!(decrypt_with_label(&h(&c["priv"]), label, &ctx, &again).unwrap(), b"round trip");
        }
    }

    #[test]
    fn key_schedule_and_transcript_vectors() {
        for v in vectors("key-schedule") {
            let mut init = h(&v["initial_init_secret"]);
            for e in v["epochs"].as_array().unwrap() {
                let ctx = h(&e["group_context"]);
                let joiner = expand_with_label(&extract(&init, &h(&e["commit_secret"])), "joiner", &ctx, NH);
                assert_eq!(joiner, h(&e["joiner_secret"]));
                let member = extract(&joiner, &h(&e["psk_secret"]));
                assert_eq!(derive_secret(&member, "welcome"), h(&e["welcome_secret"]));
                let ep = Epoch::from_secret(&expand_with_label(&member, "epoch", &ctx, NH));
                assert_eq!(ep.exporter, h(&e["exporter_secret"]));
                assert_eq!((ep.confirm.clone(), ep.membership.clone(), ep.authenticator.clone()), (h(&e["confirmation_key"]), h(&e["membership_key"]), h(&e["epoch_authenticator"])));
                let ex = &e["exporter"];
                let got = expand_with_label(&derive_secret(&ep.exporter, ex["label"].as_str().unwrap()), "exported", &hash(&h(&ex["context"])), ex["length"].as_u64().unwrap() as usize);
                assert_eq!(got, h(&ex["secret"]));
                init = ep.init;
                assert_eq!(init, h(&e["init_secret"]));
            }
        }
        for v in vectors("transcript-hashes") {
            let ac = h(&v["authenticated_content"]);
            // AuthenticatedContent = wire_format ‖ FramedContent ‖ signature<V> ‖ confirmation_tag<V>.
            let mut r = R::new(&ac[2..]);
            FramedContent::dec(&mut r).unwrap();
            let sig_end = 2 + r.i + {
                let start = r.i;
                r.vec().unwrap();
                r.i - start
            };
            let tag = r.vec().unwrap().to_vec();
            let mut cth_in = h(&v["interim_transcript_hash_before"]);
            cth_in.extend_from_slice(&ac[..sig_end]);
            let cth = hash(&cth_in).to_vec();
            assert_eq!(cth, h(&v["confirmed_transcript_hash_after"]));
            assert_eq!(mac(&h(&v["confirmation_key"]), &cth), tag);
            assert_eq!(interim(&cth, &tag), h(&v["interim_transcript_hash_after"]));
        }
    }

    #[test]
    fn tree_math_vectors() {
        let all: Vec<Value> = serde_json::from_str(include_str!("testdata/mls/tree-math.json")).unwrap();
        for v in all {
            let n = v["n_leaves"].as_u64().unwrap() as usize;
            assert_eq!(root(n), v["root"].as_u64().unwrap() as usize);
            let w = 2 * n - 1;
            for x in 0..w {
                let opt = |k: &str| v[k][x].as_u64().map(|u| u as usize);
                if x % 2 == 1 {
                    assert_eq!(Some(left(x)), opt("left"));
                    assert_eq!(Some(right(x)), opt("right"));
                }
                if x != root(n) {
                    assert_eq!(Some(parent(x)), opt("parent"));
                    let p = parent(x);
                    assert_eq!(Some(if x < p { right(p) } else { left(p) }), opt("sibling"));
                }
            }
        }
    }

    #[test]
    fn tree_validation_vectors() {
        for v in vectors("tree-validation") {
            let t = Tree::parse(&h(&v["tree"])).unwrap();
            assert_eq!(t.bytes(), h(&v["tree"]), "tree re-encodes identically");
            for (x, th) in v["tree_hashes"].as_array().unwrap().iter().enumerate() {
                assert_eq!(t.hash(x, &[]).to_vec(), h(th), "tree hash of node {x}");
            }
            for (x, res) in v["resolutions"].as_array().unwrap().iter().enumerate() {
                let want: Vec<usize> = res.as_array().unwrap().iter().map(|n| n.as_u64().unwrap() as usize).collect();
                assert_eq!(t.resolution(x), want, "resolution of node {x}");
            }
            assert!(t.parent_hashes_valid());
            let gid = h(&v["group_id"]);
            assert!(t.leaves().all(|(i, l)| l.verify(&gid, i)));
        }
    }

    #[test]
    fn welcome_vector() {
        for v in vectors("welcome") {
            let kp = parse_key_package(&h(&v["key_package"])).unwrap();
            assert!(kp.verify());
            let mut init = [0u8; 32];
            init.copy_from_slice(&h(&v["init_priv"]));
            // The welcome vector carries no ratchet tree; check the GroupSecrets / GroupInfo layers.
            let w = h(&v["welcome"]);
            let mut r = R::new(&w);
            r.u16().unwrap();
            r.u16().unwrap();
            assert_eq!(r.u16().unwrap(), SUITE);
            let secrets = r.list(|r| Ok((r.vec()?.to_vec(), HpkeCt::dec(r)?))).unwrap();
            let egi = r.vec().unwrap().to_vec();
            let (_, ct) = secrets.iter().find(|(k, _)| *k == kp.reference()).unwrap();
            let gs = decrypt_with_label(&init, "Welcome", &egi, ct).unwrap();
            let mut g = R::new(&gs);
            let joiner = g.vec().unwrap().to_vec();
            let ws = derive_secret(&extract(&joiner, &[0u8; NH]), "welcome");
            let gi = open(&expand_with_label(&ws, "key", &[], 16), &expand_with_label(&ws, "nonce", &[], 12), &[], &egi).unwrap();
            let mut r = R::new(&gi);
            GroupContext::dec(&mut r).unwrap();
            dec_exts(&mut r).unwrap();
            r.vec().unwrap();
            r.u32().unwrap();
            let tbs = r.i;
            let sig = r.vec().unwrap();
            assert!(verify_with_label(&h(&v["signer_pub"]), "GroupInfoTBS", &gi[..tbs], sig));
        }
    }

    fn arr32(b: &[u8]) -> [u8; 32] {
        b.try_into().unwrap()
    }

    /// Passive client: join by Welcome, then follow every epoch, comparing epoch authenticators.
    fn run_passive(v: &Value) -> Res<()> {
        let kp = parse_key_package(&h(&v["key_package"]))?;
        let signer = Arc::new(Signer::from_scalar(&h(&v["signature_priv"]))?);
        let psks: Vec<(Vec<u8>, Vec<u8>)> = v["external_psks"].as_array().unwrap().iter().map(|p| (h(&p["psk_id"]), h(&p["psk"]))).collect();
        let lookup = move |id: &[u8]| psks.iter().find(|(i, _)| i == id).map(|(_, p)| p.clone());
        let tree = v["ratchet_tree"].as_str().filter(|s| !s.is_empty()).map(|s| Tree::parse(&hex_decode(s).unwrap())).transpose()?;
        let mut g = Group::join(&h(&v["welcome"]), &kp, &arr32(&h(&v["init_priv"])), arr32(&h(&v["encryption_priv"])), signer, tree, &lookup)?;
        assert_eq!(g.epoch_authenticator(), &h(&v["initial_epoch_authenticator"])[..]);
        for e in v["epochs"].as_array().unwrap() {
            let cache = e["proposals"].as_array().unwrap().iter().map(|p| g.proposal(&h(p))).collect::<Res<Vec<_>>>()?;
            g = g.process_commit(&h(&e["commit"]), &cache, &lookup)?;
            assert_eq!(hex(g.epoch_authenticator()), e["epoch_authenticator"].as_str().unwrap());
        }
        Ok(())
    }

    #[test]
    fn passive_client_welcome_vectors() {
        let vs = vectors("passive-client-welcome");
        assert!(vs.len() >= 4);
        for (i, v) in vs.iter().enumerate() {
            run_passive(v).unwrap_or_else(|e| panic!("case {i}: {e}"));
        }
    }

    #[test]
    fn passive_client_commit_vectors() {
        let vs = vectors("passive-client-handling-commit");
        assert!(vs.len() >= 8);
        for (i, v) in vs.iter().enumerate() {
            run_passive(v).unwrap_or_else(|e| panic!("case {i}: {e}"));
        }
    }

    /// Our own commits (with and without UpdatePath) are accepted by our own receiver,
    /// which the vectors above validate against other implementations.
    #[test]
    fn create_commit_welcome_round_trip() {
        let es = ExternalSender { sig_key: Signer::generate().public(), cred: Credential::basic(b"gw") };
        let member = |id: u8| {
            let s = Arc::new(Signer::generate());
            let (leaf, sk) = new_leaf(&[id], &s);
            let (init_sk, init_pk) = generate_key_pair();
            let kp = KeyPackage::new(init_pk, leaf, &s);
            (s, kp, init_sk, sk)
        };
        let (sa, kpa, _, ska) = member(1);
        let a0 = Group::create(b"group", kpa.leaf.clone(), ska, sa, vec![ExternalSender::extension(std::slice::from_ref(&es))]);
        let add = |kp: &KeyPackage, r: &[u8]| Cached { reference: r.to_vec(), proposal: Proposal::Add(kp.clone()), sender: Sender::External(0) };
        // A adds B and C (no path needed for adds only).
        let (sb, kpb, ib, skb) = member(2);
        let (sc, kpc, ic, skc) = member(3);
        let out = a0.commit(&[add(&kpb, b"r1"), add(&kpc, b"r2")], false).unwrap();
        let a1 = out.next;
        let w = out.welcome.unwrap();
        let b1 = Group::join(&w, &kpb, &ib, skb, sb, None, &no_psks).unwrap();
        let c1 = Group::join(&w, &kpc, &ic, skc, sc, None, &no_psks).unwrap();
        assert_eq!((a1.epoch, b1.epoch, c1.epoch), (1, 1, 1));
        assert_eq!(a1.epoch_authenticator(), b1.epoch_authenticator());
        assert_eq!(b1.export("Discord Secure Frames v0", &[1, 0, 0, 0, 0, 0, 0, 0], 16), a1.export("Discord Secure Frames v0", &[1, 0, 0, 0, 0, 0, 0, 0], 16));
        assert_eq!(b1.members().count(), 3);
        // B commits an empty commit with a path; A and C follow.
        let out_b = b1.commit(&[], true).unwrap();
        let b2 = out_b.next;
        let a2 = a1.process_commit(&out_b.commit, &[], &no_psks).unwrap();
        let c2 = c1.process_commit(&out_b.commit, &[], &no_psks).unwrap();
        assert_eq!(a2.epoch_authenticator(), b2.epoch_authenticator());
        assert_eq!(c2.epoch_authenticator(), b2.epoch_authenticator());
        // The external sender removes A and adds D; C commits (a remove needs a path).
        let (sd, kpd, id_, skd) = member(4);
        let props = vec![Cached { reference: b"r3".to_vec(), proposal: Proposal::Remove(0), sender: Sender::External(0) }, add(&kpd, b"r4")];
        let out_c = c2.commit(&props, false).unwrap();
        assert!(out_c.commit.len() > 500, "carries an update path");
        let c3 = out_c.next;
        let b3 = b2.process_commit(&out_c.commit, &props, &no_psks).unwrap();
        assert_eq!(b3.epoch_authenticator(), c3.epoch_authenticator());
        assert!(a2.process_commit(&out_c.commit, &props, &no_psks).unwrap_err().contains("removed"));
        assert!(c2.process_commit(&out_c.commit, &props, &no_psks).unwrap_err().contains("own commit"));
        let d3 = Group::join(&out_c.welcome.unwrap(), &kpd, &id_, skd, sd, None, &no_psks).unwrap();
        assert_eq!(d3.epoch_authenticator(), c3.epoch_authenticator());
        assert_eq!(d3.members().map(|(_, l)| l.cred.body.clone()).collect::<Vec<_>>(), [vec![4], vec![2], vec![3]]);
        // D (in A's old slot) commits with a path; B and C follow.
        let out_d = d3.commit(&[], true).unwrap();
        assert_eq!(b3.process_commit(&out_d.commit, &[], &no_psks).unwrap().epoch_authenticator(), out_d.next.epoch_authenticator());
        assert_eq!(c3.process_commit(&out_d.commit, &[], &no_psks).unwrap().epoch_authenticator(), out_d.next.epoch_authenticator());
        // Tampering is caught: a flipped byte breaks the membership tag or the signature.
        let mut bad = out_d.commit.clone();
        let n = bad.len();
        bad[n - 40] ^= 1;
        assert!(b3.process_commit(&bad, &[], &no_psks).is_err());
    }
}
