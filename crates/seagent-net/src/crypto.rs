//! Small crypto helpers over `ring`: digests, HMAC (webhook signatures from
//! Slack, LINE, Feishu, WhatsApp Cloud, Twilio…), Ed25519 (Discord
//! interactions), randomness, encodings, AES-CBC for the platforms that
//! still encrypt callback bodies with it (Feishu, WeCom, DingTalk) and for
//! Olm/Megolm, AES-CTR (Matrix encrypted attachments) and X25519 with static keys.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::{digest, hmac, rand::SecureRandom, signature};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Incremental sha256 for inputs too large to hold in memory (VM images, browser archives).
pub struct Sha256Stream(digest::Context);

impl Default for Sha256Stream {
    fn default() -> Self {
        Sha256Stream(digest::Context::new(&digest::SHA256))
    }
}

impl Sha256Stream {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    /// Lowercase hex digest.
    pub fn finish_hex(self) -> String {
        hex(self.0.finish().as_ref())
    }
}

/// sha256 of a file, streamed, as lowercase hex.
pub fn sha256_file_hex(p: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256Stream::default();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finish_hex());
        }
        h.update(&buf[..n]);
    }
}

/// Only for protocols that mandate it (WebSocket handshake, WeCom/Feishu legacy signatures).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    let mut out = [0u8; 20];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut out = [0u8; 32];
    out.copy_from_slice(hmac::sign(&k, data).as_ref());
    out
}

/// Twilio request signatures.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let mut out = [0u8; 20];
    out.copy_from_slice(hmac::sign(&k, data).as_ref());
    out
}

/// Constant-time comparison for secrets and signatures.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn ed25519_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key).verify(msg, sig).is_ok()
}

/// Ed25519 public key of a 32-byte seed.
pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    use signature::KeyPair;
    signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 seed").public_key().as_ref().try_into().expect("32 bytes")
}

pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 seed").sign(msg).as_ref().try_into().expect("64 bytes")
}

/// ECDSA P-256 / SHA-256 verification of a device signature: `public_key` is the 65-byte
/// uncompressed point (WebCrypto `exportKey("raw")`, ring `public_key()`), `sig` the 64-byte
/// `r ‖ s` form both produce (IEEE P1363). Paired devices prove possession of their key with it.
pub fn p256_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    public_key.len() == 65 && public_key[0] == 4 && sig.len() == 64 && signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key).verify(msg, sig).is_ok()
}

/// A new P-256 key as PKCS#8 (device keys of native clients and tests).
pub fn p256_generate() -> Option<Vec<u8>> {
    signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &ring::rand::SystemRandom::new()).ok().map(|d| d.as_ref().to_vec())
}

/// The uncompressed public point of a PKCS#8 P-256 key.
pub fn p256_public(pkcs8: &[u8]) -> Option<Vec<u8>> {
    use signature::KeyPair;
    let k = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &ring::rand::SystemRandom::new()).ok()?;
    Some(k.public_key().as_ref().to_vec())
}

/// `r ‖ s` signature over `msg` with a PKCS#8 P-256 key.
pub fn p256_sign(pkcs8: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let rng = ring::rand::SystemRandom::new();
    let k = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng).ok()?;
    k.sign(&rng, msg).ok().map(|s| s.as_ref().to_vec())
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    ring::rand::SystemRandom::new().fill(&mut v).expect("system randomness unavailable");
    v
}

/// URL-safe random token (`n` random bytes).
pub fn random_token(n: usize) -> String {
    b64url(&random_bytes(n))
}

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s.trim()).ok()
}

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim().trim_end_matches('=')).ok()
}

pub fn hex(data: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() & 1 == 1 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// PKCE (RFC 7636) S256 pair: (verifier, challenge).
pub fn pkce_pair() -> (String, String) {
    let verifier = random_token(32);
    let challenge = b64url(&sha256(verifier.as_bytes()));
    (verifier, challenge)
}

// ───────────── X25519 (RFC 7748) ─────────────

/// X25519 over GF(2^255-19) with 51-bit limbs. ring's agreement API only offers
/// ephemeral private keys; Reef and Matrix Olm need persistent keys.
pub mod x25519 {
    type Fe = [u64; 5];
    const M: u64 = (1 << 51) - 1;

    fn load(b: &[u8; 32]) -> Fe {
        let w = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        [w(0) & M, (w(6) >> 3) & M, (w(12) >> 6) & M, (w(19) >> 1) & M, (w(24) >> 12) & M]
    }

    fn weak(mut a: Fe) -> Fe {
        for i in 0..4 {
            a[i + 1] += a[i] >> 51;
            a[i] &= M;
        }
        let c = a[4] >> 51;
        a[4] &= M;
        a[0] += 19 * c;
        a[1] += a[0] >> 51;
        a[0] &= M;
        a
    }

    fn add(a: &Fe, b: &Fe) -> Fe {
        weak([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    fn sub(a: &Fe, b: &Fe) -> Fe {
        // a + 2p - b keeps every limb positive (inputs are weakly reduced).
        const P2: [u64; 5] = [0xFFFFFFFFFFFDA, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE];
        weak([a[0] + P2[0] - b[0], a[1] + P2[1] - b[1], a[2] + P2[2] - b[2], a[3] + P2[3] - b[3], a[4] + P2[4] - b[4]])
    }

    fn reduce(mut r: [u128; 5]) -> Fe {
        let m = M as u128;
        for i in 0..4 {
            r[i + 1] += r[i] >> 51;
            r[i] &= m;
        }
        let c = r[4] >> 51;
        r[4] &= m;
        r[0] += c * 19;
        r[1] += r[0] >> 51;
        r[0] &= m;
        weak([r[0] as u64, r[1] as u64, r[2] as u64, r[3] as u64, r[4] as u64])
    }

    fn mul(a: &Fe, b: &Fe) -> Fe {
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let (b1, b2, b3, b4) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
        reduce([
            m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1),
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2),
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3),
            m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4),
            m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
        ])
    }

    fn sq(a: &Fe) -> Fe {
        mul(a, a)
    }

    fn mul_small(a: &Fe, k: u64) -> Fe {
        reduce([a[0] as u128 * k as u128, a[1] as u128 * k as u128, a[2] as u128 * k as u128, a[3] as u128 * k as u128, a[4] as u128 * k as u128])
    }

    fn pow2k(a: &Fe, k: usize) -> Fe {
        let mut r = *a;
        for _ in 0..k {
            r = sq(&r);
        }
        r
    }

    fn invert(z: &Fe) -> Fe {
        let z2 = sq(z);
        let z9 = mul(&pow2k(&z2, 2), z);
        let z11 = mul(&z9, &z2);
        let z5 = mul(&sq(&z11), &z9);
        let z10 = mul(&pow2k(&z5, 5), &z5);
        let z20 = mul(&pow2k(&z10, 10), &z10);
        let z40 = mul(&pow2k(&z20, 20), &z20);
        let z50 = mul(&pow2k(&z40, 10), &z10);
        let z100 = mul(&pow2k(&z50, 50), &z50);
        let z200 = mul(&pow2k(&z100, 100), &z100);
        let z250 = mul(&pow2k(&z200, 50), &z50);
        mul(&pow2k(&z250, 5), &z11)
    }

    fn store(a: &Fe) -> [u8; 32] {
        let mut h = weak(weak(*a));
        let mut q = (h[0] + 19) >> 51;
        for limb in &h[1..] {
            q = (limb + q) >> 51;
        }
        h[0] += 19 * q;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= M;
        }
        h[4] &= M;
        let mut out = [0u8; 32];
        let (mut acc, mut bits, mut idx) = (0u128, 0, 0);
        for limb in h {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 && idx < 32 {
                out[idx] = acc as u8;
                acc >>= 8;
                bits -= 8;
                idx += 1;
            }
        }
        if idx < 32 {
            out[idx] = acc as u8;
        }
        out
    }

    fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
        }
    }

    /// `X25519(k, u)` with RFC 7748 clamping.
    pub fn scalarmult(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        let mut k = *k;
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        let x1 = load(u);
        let (mut x2, mut z2, mut x3, mut z3): (Fe, Fe, Fe, Fe) = ([1, 0, 0, 0, 0], [0; 5], x1, [1, 0, 0, 0, 0]);
        let mut swap = 0u64;
        for t in (0..255).rev() {
            let bit = ((k[t / 8] >> (t % 8)) & 1) as u64;
            swap ^= bit;
            cswap(swap, &mut x2, &mut x3);
            cswap(swap, &mut z2, &mut z3);
            swap = bit;
            let a = add(&x2, &z2);
            let aa = sq(&a);
            let b = sub(&x2, &z2);
            let bb = sq(&b);
            let e = sub(&aa, &bb);
            let c = add(&x3, &z3);
            let d = sub(&x3, &z3);
            let da = mul(&d, &a);
            let cb = mul(&c, &b);
            x3 = sq(&add(&da, &cb));
            z3 = mul(&x1, &sq(&sub(&da, &cb)));
            x2 = mul(&aa, &bb);
            z2 = mul(&e, &add(&aa, &mul_small(&e, 121665)));
        }
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        store(&mul(&x2, &invert(&z2)))
    }

    pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
        let mut nine = [0u8; 32];
        nine[0] = 9;
        scalarmult(secret, &nine)
    }

    /// Shared secret; `None` for a low-order peer key (all-zero output).
    pub fn shared(secret: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
        let s = scalarmult(secret, peer);
        (s != [0u8; 32]).then_some(s)
    }
}

// ───────────── AES (FIPS-197) with CBC, PKCS#7 ─────────────
// ring only exposes AEAD modes; a few chat platforms still use AES-256-CBC
// for callback payloads, so a compact table-free implementation lives here.

const SBOX: [u8; 256] = {
    let mut s = [0u8; 256];
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        // p ← p·3, q ← q/3 in GF(2^8)
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1b } else { 0 };
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        s[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s[0] = 0x63;
    s
};

const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

pub struct Aes {
    rk: Vec<[u8; 16]>,
}

impl Aes {
    /// 16, 24 or 32 byte key.
    pub fn new(key: &[u8]) -> Option<Aes> {
        let nk = key.len() / 4;
        if !matches!(key.len(), 16 | 24 | 32) {
            return None;
        }
        let nr = nk + 6;
        let mut w: Vec<[u8; 4]> = key.chunks(4).map(|c| [c[0], c[1], c[2], c[3]]).collect();
        let mut rcon = 1u8;
        for i in nk..4 * (nr + 1) {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = [SBOX[t[1] as usize] ^ rcon, SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| SBOX[b as usize]);
            }
            let p = w[i - nk];
            w.push([p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]]);
        }
        let rk = w
            .chunks(4)
            .map(|c| {
                let mut k = [0u8; 16];
                for (j, word) in c.iter().enumerate() {
                    k[4 * j..4 * j + 4].copy_from_slice(word);
                }
                k
            })
            .collect();
        Some(Aes { rk })
    }

    pub fn encrypt_block(&self, b: &mut [u8; 16]) {
        let nr = self.rk.len() - 1;
        xor16(b, &self.rk[0]);
        for (r, k) in self.rk.iter().enumerate().skip(1) {
            for x in b.iter_mut() {
                *x = SBOX[*x as usize];
            }
            shift_rows(b);
            if r != nr {
                mix_columns(b);
            }
            xor16(b, k);
        }
    }

    pub fn decrypt_block(&self, b: &mut [u8; 16]) {
        let nr = self.rk.len() - 1;
        xor16(b, &self.rk[nr]);
        for r in (0..nr).rev() {
            inv_shift_rows(b);
            for x in b.iter_mut() {
                *x = INV_SBOX[*x as usize];
            }
            xor16(b, &self.rk[r]);
            if r != 0 {
                inv_mix_columns(b);
            }
        }
    }

    pub fn cbc_encrypt(&self, iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        let pad = 16 - plain.len() % 16;
        let mut data = plain.to_vec();
        data.extend(std::iter::repeat_n(pad as u8, pad));
        let mut prev = *iv;
        for chunk in data.chunks_mut(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            xor16(&mut b, &prev);
            self.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
            prev = b;
        }
        data
    }

    /// CTR mode (128-bit big-endian counter block starting at `iv`); encrypt = decrypt.
    pub fn ctr_apply(&self, iv: &[u8; 16], data: &mut [u8]) {
        let mut ctr = u128::from_be_bytes(*iv);
        for chunk in data.chunks_mut(16) {
            let mut ks = ctr.to_be_bytes();
            self.encrypt_block(&mut ks);
            chunk.iter_mut().zip(ks).for_each(|(d, k)| *d ^= k);
            ctr = ctr.wrapping_add(1);
        }
    }

    /// `None` on bad length or padding.
    pub fn cbc_decrypt(&self, iv: &[u8; 16], cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.is_empty() || cipher.len() & 15 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(cipher.len());
        let mut prev = *iv;
        for chunk in cipher.chunks(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            let c = b;
            self.decrypt_block(&mut b);
            xor16(&mut b, &prev);
            out.extend_from_slice(&b);
            prev = c;
        }
        // WeCom pads to 32-byte blocks with PKCS#7, so accept pad values up to 32.
        let pad = *out.last()? as usize;
        if pad == 0 || pad > 32 || pad > out.len() || !out[out.len() - pad..].iter().all(|&x| x as usize == pad) {
            return None;
        }
        out.truncate(out.len() - pad);
        Some(out)
    }
}

fn xor16(b: &mut [u8; 16], k: &[u8; 16]) {
    for i in 0..16 {
        b[i] ^= k[i];
    }
}

fn shift_rows(b: &mut [u8; 16]) {
    let s = *b;
    for c in 0..4 {
        for r in 0..4 {
            b[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    }
}

fn inv_shift_rows(b: &mut [u8; 16]) {
    let s = *b;
    for c in 0..4 {
        for r in 0..4 {
            b[4 * ((c + r) % 4) + r] = s[4 * c + r];
        }
    }
}

fn mix_columns(b: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [b[4 * c], b[4 * c + 1], b[4 * c + 2], b[4 * c + 3]];
        b[4 * c] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3];
        b[4 * c + 1] = a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3];
        b[4 * c + 2] = a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3]);
        b[4 * c + 3] = (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3]);
    }
}

fn inv_mix_columns(b: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [b[4 * c], b[4 * c + 1], b[4 * c + 2], b[4 * c + 3]];
        for r in 0..4 {
            b[4 * c + r] = gmul(a[r], 14) ^ gmul(a[(r + 1) % 4], 11) ^ gmul(a[(r + 2) % 4], 13) ^ gmul(a[(r + 3) % 4], 9);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_device_signatures_verify_and_tampering_fails() {
        let k = p256_generate().unwrap();
        let pk = p256_public(&k).unwrap();
        assert_eq!((pk.len(), pk[0]), (65, 4));
        let sig = p256_sign(&k, b"seagent-device-refresh|v1|h|d|1|n").unwrap();
        assert_eq!(sig.len(), 64);
        assert!(p256_verify(&pk, b"seagent-device-refresh|v1|h|d|1|n", &sig));
        assert!(!p256_verify(&pk, b"seagent-device-refresh|v1|h|d|2|n", &sig), "another message");
        let other = p256_public(&p256_generate().unwrap()).unwrap();
        assert!(!p256_verify(&other, b"seagent-device-refresh|v1|h|d|1|n", &sig), "another key");
        assert!(!p256_verify(&pk[1..], b"x", &sig) && !p256_verify(&pk, b"x", &sig[..63]));
    }

    #[test]
    fn digests_and_macs_match_known_vectors() {
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        // RFC 4231 test case 2
        assert_eq!(hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(hex(&hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog")), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"ab", b"abc"));
    }

    #[test]
    fn encodings_round_trip() {
        assert_eq!(b64(b"hello"), "aGVsbG8=");
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(hex_decode("00ff10").unwrap(), vec![0, 255, 16]);
        assert!(hex_decode("abc").is_none() && hex_decode("zz").is_none());
        let (v, c) = pkce_pair();
        assert_eq!(c, b64url(&sha256(v.as_bytes())));
        assert!(v.len() >= 43);
    }

    #[test]
    fn ed25519_verifies_rfc8032_vector() {
        // RFC 8032 §7.1 test 1 (empty message)
        let pk = hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let sig = hex_decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        assert!(ed25519_verify(&pk, b"", &sig));
        assert!(!ed25519_verify(&pk, b"x", &sig));
        let seed: [u8; 32] = hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap().try_into().unwrap();
        assert_eq!(ed25519_public(&seed).to_vec(), pk);
        assert_eq!(ed25519_sign(&seed, b"").to_vec(), sig);
    }

    #[test]
    fn aes_matches_fips197_and_cbc_round_trips() {
        let key = hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let aes = Aes::new(&key).unwrap();
        let mut b = [0u8; 16];
        b.copy_from_slice(&hex_decode("00112233445566778899aabbccddeeff").unwrap());
        aes.encrypt_block(&mut b);
        assert_eq!(hex(&b), "8ea2b7ca516745bfeafc49904b496089");
        aes.decrypt_block(&mut b);
        assert_eq!(hex(&b), "00112233445566778899aabbccddeeff");
        let k128 = Aes::new(&hex_decode("000102030405060708090a0b0c0d0e0f").unwrap()).unwrap();
        b.copy_from_slice(&hex_decode("00112233445566778899aabbccddeeff").unwrap());
        k128.encrypt_block(&mut b);
        assert_eq!(hex(&b), "69c4e0d86a7b0430d8cdb78070b4c55a");
        let iv = [7u8; 16];
        for msg in [&b""[..], b"x", b"exactly sixteen!", "飛書回呼內容".as_bytes()] {
            let c = aes.cbc_encrypt(&iv, msg);
            assert_eq!(c.len() % 16, 0);
            assert_eq!(aes.cbc_decrypt(&iv, &c).unwrap(), msg);
        }
        assert!(aes.cbc_decrypt(&iv, &[1u8; 15]).is_none());
        // SP 800-38A F.5.5 CTR-AES256 (counter carries across a byte boundary), plus a partial block.
        let ctr = Aes::new(&hex_decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap()).unwrap();
        let iv: [u8; 16] = hex_decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap().try_into().unwrap();
        let mut d = hex_decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
        ctr.ctr_apply(&iv, &mut d);
        assert_eq!(hex(&d), "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
        let mut p = d[..20].to_vec();
        ctr.ctr_apply(&iv, &mut p);
        assert_eq!(hex(&p), "6bc1bee22e409f96e93d7e117393172aae2d8a57");
        assert!(Aes::new(&[0u8; 10]).is_none());
    }
}
