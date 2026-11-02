//! secp256k1 / BIP-340 Schnorr, x-only ECDH, bech32 + NIP-19, and the Nostr
//! payload ciphers (NIP-04 AES-256-CBC, NIP-44 v2 ChaCha20 + HMAC) shared by
//! the `nostr` and `buzz` channels. Written from the specs (BIP-340, NIP-19,
//! NIP-04, NIP-44, RFC 8439); the Python reference is Hermes' `nostr_auth.py`.
//!
//! Field and scalar arithmetic use 4×64-bit limbs with branch-free reduction
//! (2^256 ≡ c mod m), points use complete projective addition formulas
//! (Renes–Costello–Batina, a = 0) so there are no exceptional cases, and
//! scalar multiplication is a fixed 4-bit window with a constant-time table
//! scan. Verification paths are not constant time (all inputs are public).

use ark_net::crypto::{hmac_sha256, random_bytes, sha256};

type U256 = [u64; 4]; // little-endian limbs

fn from_be(b: &[u8; 32]) -> U256 {
    let mut r = [0u64; 4];
    for (i, limb) in r.iter_mut().enumerate() {
        let off = 32 - 8 * (i + 1);
        *limb = u64::from_be_bytes(b[off..off + 8].try_into().unwrap());
    }
    r
}

fn to_be(a: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in a.iter().enumerate() {
        let off = 32 - 8 * (i + 1);
        out[off..off + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn add_raw(a: &U256, b: &U256) -> (U256, u64) {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let t = a[i] as u128 + b[i] as u128 + carry as u128;
        r[i] = t as u64;
        carry = (t >> 64) as u64;
    }
    (r, carry)
}

fn sub_raw(a: &U256, b: &U256) -> (U256, u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let t = (a[i] as u128).wrapping_sub(b[i] as u128 + borrow as u128);
        r[i] = t as u64;
        borrow = (t >> 127) as u64;
    }
    (r, borrow)
}

/// mask all-ones → a, zero → b.
fn select(mask: u64, a: &U256, b: &U256) -> U256 {
    [(a[0] & mask) | (b[0] & !mask), (a[1] & mask) | (b[1] & !mask), (a[2] & mask) | (b[2] & !mask), (a[3] & mask) | (b[3] & !mask)]
}

fn eq_mask(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    ((x | x.wrapping_neg()) >> 63).wrapping_sub(1)
}

fn is_zero(a: &U256) -> bool {
    (a[0] | a[1] | a[2] | a[3]) == 0
}

fn lt(a: &U256, b: &U256) -> bool {
    sub_raw(a, b).1 == 1
}

/// A modulus m > 2^255 with c = 2^256 - m (< 2^192).
struct Modulus {
    m: U256,
    c: [u64; 3],
}

const P: Modulus = Modulus { m: [0xFFFF_FFFE_FFFF_FC2F, u64::MAX, u64::MAX, u64::MAX], c: [0x1_0000_03D1, 0, 0] };
const N: Modulus = Modulus { m: [0xBFD2_5E8C_D036_4141, 0xBAAE_DCE6_AF48_A03B, 0xFFFF_FFFF_FFFF_FFFE, u64::MAX], c: [0x402D_A173_2FC9_BEBF, 0x4551_2319_50B7_5FC4, 1] };

impl Modulus {
    /// L + H·c where x = H·2^256 + L.
    fn fold(&self, x: &[u64; 8]) -> [u64; 8] {
        let mut r = [0u64; 8];
        r[..4].copy_from_slice(&x[..4]);
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..3 {
                let t = (x[4 + i] as u128) * (self.c[j] as u128) + r[i + j] as u128 + carry as u128;
                r[i + j] = t as u64;
                carry = (t >> 64) as u64;
            }
            for limb in r.iter_mut().skip(i + 3) {
                let t = *limb as u128 + carry as u128;
                *limb = t as u64;
                carry = (t >> 64) as u64;
            }
        }
        r
    }

    fn cond_sub(&self, a: &U256) -> U256 {
        let (t, borrow) = sub_raw(a, &self.m);
        select(0u64.wrapping_sub(borrow), a, &t)
    }

    /// Any 512-bit value mod m. Four folds bring it below 2^256 (< 2m).
    fn reduce_wide(&self, x: &[u64; 8]) -> U256 {
        let mut x = *x;
        for _ in 0..4 {
            x = self.fold(&x);
        }
        self.cond_sub(&[x[0], x[1], x[2], x[3]])
    }

    fn reduce(&self, a: &U256) -> U256 {
        self.cond_sub(a)
    }

    fn mul(&self, a: &U256, b: &U256) -> U256 {
        let mut r = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let t = a[i] as u128 * b[j] as u128 + r[i + j] as u128 + carry as u128;
                r[i + j] = t as u64;
                carry = (t >> 64) as u64;
            }
            r[i + 4] = carry;
        }
        self.reduce_wide(&r)
    }

    fn add(&self, a: &U256, b: &U256) -> U256 {
        let (s, carry) = add_raw(a, b);
        self.reduce_wide(&[s[0], s[1], s[2], s[3], carry, 0, 0, 0])
    }

    fn neg(&self, a: &U256) -> U256 {
        self.cond_sub(&sub_raw(&self.m, a).0)
    }

    fn sub(&self, a: &U256, b: &U256) -> U256 {
        self.add(a, &self.neg(b))
    }

    /// Square-and-multiply; the exponent is public.
    fn pow(&self, a: &U256, e: &U256) -> U256 {
        let mut r: U256 = [1, 0, 0, 0];
        for i in (0..256).rev() {
            r = self.mul(&r, &r);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.mul(&r, a);
            }
        }
        r
    }

    fn inv(&self, a: &U256) -> U256 {
        self.pow(a, &sub_raw(&self.m, &[2, 0, 0, 0]).0)
    }
}

const GX: U256 = [0x59F2_815B_16F8_1798, 0x029B_FCDB_2DCE_28D9, 0x55A0_6295_CE87_0B07, 0x79BE_667E_F9DC_BBAC];
const GY: U256 = [0x9C47_D08F_FB10_D4B8, 0xFD17_B448_A685_5419, 0x5DA4_FBFC_0E11_08A8, 0x483A_DA77_26A3_C465];
const B3: U256 = [21, 0, 0, 0];

/// Projective point (X:Y:Z), identity = (0:1:0).
#[derive(Clone, Copy)]
struct Point {
    x: U256,
    y: U256,
    z: U256,
}

impl Point {
    const IDENTITY: Point = Point { x: [0; 4], y: [1, 0, 0, 0], z: [0; 4] };
    const G: Point = Point { x: GX, y: GY, z: [1, 0, 0, 0] };

    /// Complete addition (RCB 2015, algorithm 7, a = 0): valid for doubling and the identity.
    fn add(&self, q: &Point) -> Point {
        let (m, a, s) = (|x: &U256, y: &U256| P.mul(x, y), |x: &U256, y: &U256| P.add(x, y), |x: &U256, y: &U256| P.sub(x, y));
        let (x1, y1, z1, x2, y2, z2) = (&self.x, &self.y, &self.z, &q.x, &q.y, &q.z);
        let mut t0 = m(x1, x2);
        let mut t1 = m(y1, y2);
        let mut t2 = m(z1, z2);
        let mut t3 = a(x1, y1);
        let mut t4 = a(x2, y2);
        t3 = m(&t3, &t4);
        t4 = a(&t0, &t1);
        t3 = s(&t3, &t4);
        t4 = a(y1, z1);
        let mut x3 = a(y2, z2);
        t4 = m(&t4, &x3);
        x3 = a(&t1, &t2);
        t4 = s(&t4, &x3);
        x3 = a(x1, z1);
        let mut y3 = a(x2, z2);
        x3 = m(&x3, &y3);
        y3 = a(&t0, &t2);
        y3 = s(&x3, &y3);
        x3 = a(&t0, &t0);
        t0 = a(&x3, &t0);
        t2 = m(&B3, &t2);
        let mut z3 = a(&t1, &t2);
        t1 = s(&t1, &t2);
        y3 = m(&B3, &y3);
        x3 = m(&t4, &y3);
        t2 = m(&t3, &t1);
        x3 = s(&t2, &x3);
        y3 = m(&y3, &t0);
        t1 = m(&t1, &z3);
        y3 = a(&t1, &y3);
        t0 = m(&t0, &t3);
        z3 = m(&z3, &t4);
        z3 = a(&z3, &t0);
        Point { x: x3, y: y3, z: z3 }
    }

    fn select(mask: u64, a: &Point, b: &Point) -> Point {
        Point { x: select(mask, &a.x, &b.x), y: select(mask, &a.y, &b.y), z: select(mask, &a.z, &b.z) }
    }

    /// k·self with a fixed 4-bit window and constant-time table lookup.
    fn mul(&self, k: &U256) -> Point {
        let mut table = [Point::IDENTITY; 16];
        table[1] = *self;
        for i in 2..16 {
            table[i] = table[i - 1].add(self);
        }
        let mut r = Point::IDENTITY;
        for limb in (0..4).rev() {
            for nib in (0..16).rev() {
                for _ in 0..4 {
                    r = r.add(&r);
                }
                let idx = (k[limb] >> (nib * 4)) & 15;
                let mut sel = Point::IDENTITY;
                for (i, t) in table.iter().enumerate() {
                    sel = Point::select(eq_mask(i as u64, idx), t, &sel);
                }
                r = r.add(&sel);
            }
        }
        r
    }

    /// Affine (x, y); `None` for the identity.
    fn affine(&self) -> Option<(U256, U256)> {
        if is_zero(&self.z) {
            return None;
        }
        let zi = P.inv(&self.z);
        Some((P.mul(&self.x, &zi), P.mul(&self.y, &zi)))
    }
}

/// The curve point with x-coordinate `x` and even y (BIP-340 `lift_x`).
fn lift_x(x: &[u8; 32]) -> Option<Point> {
    let x = from_be(x);
    if !lt(&x, &P.m) {
        return None;
    }
    let c = P.add(&P.mul(&P.mul(&x, &x), &x), &[7, 0, 0, 0]);
    let e = {
        let (p1, _) = add_raw(&P.m, &[1, 0, 0, 0]);
        [(p1[0] >> 2) | (p1[1] << 62), (p1[1] >> 2) | (p1[2] << 62), (p1[2] >> 2) | (p1[3] << 62), p1[3] >> 2]
    };
    let y = P.pow(&c, &e);
    if P.mul(&y, &y) != c {
        return None;
    }
    let y = if y[0] & 1 == 1 { P.neg(&y) } else { y };
    Some(Point { x, y, z: [1, 0, 0, 0] })
}

fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let th = sha256(tag.as_bytes());
    let mut buf = Vec::with_capacity(64 + parts.iter().map(|p| p.len()).sum::<usize>());
    buf.extend_from_slice(&th);
    buf.extend_from_slice(&th);
    for p in parts {
        buf.extend_from_slice(p);
    }
    sha256(&buf)
}

fn scalar(sk: &[u8; 32]) -> Option<U256> {
    let d = from_be(sk);
    (!is_zero(&d) && lt(&d, &N.m)).then_some(d)
}

/// Is this a valid secret key (1 ≤ k < n)?
pub fn valid_secret(sk: &[u8; 32]) -> bool {
    scalar(sk).is_some()
}

/// A fresh random secret key.
pub fn random_secret() -> [u8; 32] {
    loop {
        let b: [u8; 32] = random_bytes(32).try_into().unwrap();
        if valid_secret(&b) {
            return b;
        }
    }
}

/// BIP-340 x-only public key.
pub fn xonly_pubkey(sk: &[u8; 32]) -> Option<[u8; 32]> {
    let d = scalar(sk)?;
    let (x, _) = Point::G.mul(&d).affine()?;
    Some(to_be(&x))
}

/// BIP-340 signature over `msg` (any length) with auxiliary randomness `aux`.
pub fn schnorr_sign(sk: &[u8; 32], msg: &[u8], aux: &[u8; 32]) -> Option<[u8; 64]> {
    let d0 = scalar(sk)?;
    let (px, py) = Point::G.mul(&d0).affine()?;
    let pbytes = to_be(&px);
    let d = select(0u64.wrapping_sub(py[0] & 1), &N.neg(&d0), &d0);
    let t: Vec<u8> = to_be(&d).iter().zip(tagged_hash("BIP0340/aux", &[aux])).map(|(a, b)| a ^ b).collect();
    let rand = tagged_hash("BIP0340/nonce", &[&t, &pbytes, msg]);
    let k0 = N.reduce(&from_be(&rand));
    if is_zero(&k0) {
        return None;
    }
    let (rx, ry) = Point::G.mul(&k0).affine()?;
    let k = select(0u64.wrapping_sub(ry[0] & 1), &N.neg(&k0), &k0);
    let rbytes = to_be(&rx);
    let e = N.reduce(&from_be(&tagged_hash("BIP0340/challenge", &[&rbytes, &pbytes, msg])));
    let s = N.add(&k, &N.mul(&e, &d));
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rbytes);
    sig[32..].copy_from_slice(&to_be(&s));
    Some(sig)
}

/// Sign with fresh auxiliary randomness.
pub fn sign(sk: &[u8; 32], msg: &[u8]) -> Option<[u8; 64]> {
    let aux: [u8; 32] = random_bytes(32).try_into().unwrap();
    schnorr_sign(sk, msg, &aux)
}

/// BIP-340 verification.
pub fn schnorr_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(p) = lift_x(pk) else { return false };
    let r = from_be(sig[..32].try_into().unwrap());
    let s = from_be(sig[32..].try_into().unwrap());
    if !lt(&r, &P.m) || !lt(&s, &N.m) {
        return false;
    }
    let e = N.reduce(&from_be(&tagged_hash("BIP0340/challenge", &[&sig[..32], pk, msg])));
    let rp = Point::G.mul(&s).add(&p.mul(&N.neg(&e)));
    match rp.affine() {
        Some((x, y)) => y[0] & 1 == 0 && x == r,
        None => false,
    }
}

/// x-coordinate of sk·P for an x-only public key (Nostr ECDH, unhashed).
pub fn ecdh_x(sk: &[u8; 32], pk: &[u8; 32]) -> Option<[u8; 32]> {
    let d = scalar(sk)?;
    let p = lift_x(pk)?;
    let (x, _) = p.mul(&d).affine()?;
    Some(to_be(&x))
}

// ---------------------------------------------------------------- bech32 / NIP-19

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1FF_FFFF) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|b| b & 31));
    v
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &v in data {
        if (v as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

pub fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let d5 = convert_bits(data, 8, 5, true).unwrap_or_default();
    let mut v = hrp_expand(hrp);
    v.extend(&d5);
    v.extend([0u8; 6]);
    let pm = polymod(&v) ^ 1;
    let mut s = format!("{hrp}1");
    for b in &d5 {
        s.push(CHARSET[*b as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// (hrp, bytes). No 90-character cap: NIP-19 TLV strings are longer.
pub fn bech32_decode(s: &str) -> Option<(String, Vec<u8>)> {
    if s.chars().any(|c| c.is_ascii_lowercase()) && s.chars().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let s = s.to_ascii_lowercase();
    let sep = s.rfind('1')?;
    if sep < 1 || sep + 7 > s.len() || s.len() > 5000 {
        return None;
    }
    let hrp = &s[..sep];
    let data: Vec<u8> = s[sep + 1..].bytes().map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8)).collect::<Option<_>>()?;
    let mut v = hrp_expand(hrp);
    v.extend(&data);
    if polymod(&v) != 1 {
        return None;
    }
    let bytes = convert_bits(&data[..data.len() - 6], 5, 8, false)?;
    Some((hrp.to_string(), bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nip19 {
    Npub([u8; 32]),
    Nsec([u8; 32]),
    Note([u8; 32]),
    Nprofile { pubkey: [u8; 32], relays: Vec<String> },
    Nevent { id: [u8; 32], relays: Vec<String>, author: Option<[u8; 32]>, kind: Option<u32> },
}

fn tlv(data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let t = data[i];
        let l = *data.get(i + 1)? as usize;
        let v = data.get(i + 2..i + 2 + l)?;
        out.push((t, v));
        i += 2 + l;
    }
    Some(out)
}

pub fn nip19_decode(s: &str) -> Result<Nip19, String> {
    let s = s.trim().trim_start_matches("nostr:");
    let (hrp, data) = bech32_decode(s).ok_or("invalid bech32 (bad checksum or characters)")?;
    let b32 = |d: &[u8]| -> Result<[u8; 32], String> { d.try_into().map_err(|_| format!("{hrp} must encode 32 bytes")) };
    match hrp.as_str() {
        "npub" => Ok(Nip19::Npub(b32(&data)?)),
        "nsec" => Ok(Nip19::Nsec(b32(&data)?)),
        "note" => Ok(Nip19::Note(b32(&data)?)),
        "nprofile" | "nevent" => {
            let items = tlv(&data).ok_or("truncated TLV")?;
            let mut main = None;
            let mut relays = Vec::new();
            let mut author = None;
            let mut kind = None;
            for (t, v) in items {
                match t {
                    0 if main.is_none() => main = Some(b32(v)?),
                    1 => relays.push(String::from_utf8_lossy(v).into_owned()),
                    2 if hrp == "nevent" => author = Some(b32(v)?),
                    3 if hrp == "nevent" && v.len() == 4 => kind = Some(u32::from_be_bytes(v.try_into().unwrap())),
                    _ => {}
                }
            }
            let main = main.ok_or("TLV without the special (type 0) entry")?;
            Ok(if hrp == "nprofile" { Nip19::Nprofile { pubkey: main, relays } } else { Nip19::Nevent { id: main, relays, author, kind } })
        }
        other => Err(format!("unsupported NIP-19 prefix {other}")),
    }
}

pub fn npub(pk: &[u8; 32]) -> String {
    bech32_encode("npub", pk)
}
pub fn nsec(sk: &[u8; 32]) -> String {
    bech32_encode("nsec", sk)
}
pub fn note(id: &[u8; 32]) -> String {
    bech32_encode("note", id)
}
pub fn nprofile(pk: &[u8; 32], relays: &[String]) -> String {
    let mut d = vec![0u8, 32];
    d.extend_from_slice(pk);
    for r in relays.iter().filter(|r| r.len() < 256) {
        d.push(1);
        d.push(r.len() as u8);
        d.extend_from_slice(r.as_bytes());
    }
    bech32_encode("nprofile", &d)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = ark_net::crypto::hex_decode(s.trim())?;
    b.try_into().ok()
}

/// Secret key from 64 hex chars or `nsec1…`.
pub fn parse_secret_key(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    let k = if s.to_ascii_lowercase().starts_with("nsec1") {
        match nip19_decode(s)? {
            Nip19::Nsec(k) => k,
            _ => return Err("not an nsec".into()),
        }
    } else {
        hex32(s).ok_or("private key must be 64 hex characters or nsec")?
    };
    if !valid_secret(&k) {
        return Err("private key is outside the secp256k1 range".into());
    }
    Ok(k)
}

/// Public key from 64 hex chars, `npub1…`, `nprofile1…` or `nostr:` URIs; lowercase hex out.
pub fn parse_pubkey(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim().trim_start_matches("nostr:");
    let low = s.to_ascii_lowercase();
    if low.starts_with("npub1") || low.starts_with("nprofile1") {
        return match nip19_decode(s)? {
            Nip19::Npub(k) | Nip19::Nprofile { pubkey: k, .. } => Ok(k),
            _ => Err("not a public key".into()),
        };
    }
    hex32(s).ok_or_else(|| "pubkey must be 64 hex characters or npub".to_string())
}

// ---------------------------------------------------------------- ChaCha20 (RFC 8439)

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn chacha_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let w = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let mut st = [0u32; 16];
    st[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        st[4 + i] = w(&key[4 * i..4 * i + 4]);
    }
    st[12] = counter;
    for i in 0..3 {
        st[13 + i] = w(&nonce[4 * i..4 * i + 4]);
    }
    let mut x = st;
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&x[i].wrapping_add(st[i]).to_le_bytes());
    }
    out
}

/// XOR `data` with the ChaCha20 keystream starting at block `counter`.
pub fn chacha20(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let ks = chacha_block(key, nonce, counter.wrapping_add(i as u32));
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
}

// ---------------------------------------------------------------- NIP-44 v2

pub mod nip44 {
    use super::*;
    use ring::hkdf;

    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    /// HKDF-extract(salt = "nip44-v2", ikm = shared x).
    pub fn conversation_key(sk: &[u8; 32], pk: &[u8; 32]) -> Option<[u8; 32]> {
        Some(hmac_sha256(b"nip44-v2", &ecdh_x(sk, pk)?))
    }

    fn message_keys(conv: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, conv);
        let info = [&nonce[..]];
        let okm = prk.expand(&info, Len(76)).expect("hkdf length");
        let mut k = [0u8; 76];
        okm.fill(&mut k).expect("hkdf fill");
        (k[..32].try_into().unwrap(), k[32..44].try_into().unwrap(), k[44..].try_into().unwrap())
    }

    pub fn calc_padded_len(len: usize) -> usize {
        if len <= 32 {
            return 32;
        }
        let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros());
        let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
        chunk * ((len - 1) / chunk + 1)
    }

    pub fn encrypt(conv: &[u8; 32], plaintext: &str, nonce: Option<[u8; 32]>) -> Result<String, String> {
        let pt = plaintext.as_bytes();
        if pt.is_empty() || pt.len() > 65535 {
            return Err("NIP-44 plaintext must be 1..65535 bytes".into());
        }
        let nonce = nonce.unwrap_or_else(|| random_bytes(32).try_into().unwrap());
        let (ck, cn, hk) = message_keys(conv, &nonce);
        let mut padded = Vec::with_capacity(2 + calc_padded_len(pt.len()));
        padded.extend_from_slice(&(pt.len() as u16).to_be_bytes());
        padded.extend_from_slice(pt);
        padded.resize(2 + calc_padded_len(pt.len()), 0);
        chacha20(&ck, &cn, 0, &mut padded);
        let mut mac_in = nonce.to_vec();
        mac_in.extend_from_slice(&padded);
        let mac = hmac_sha256(&hk, &mac_in);
        let mut out = vec![2u8];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&padded);
        out.extend_from_slice(&mac);
        Ok(ark_net::crypto::b64(&out))
    }

    pub fn decrypt(conv: &[u8; 32], payload: &str) -> Result<String, String> {
        if payload.starts_with('#') {
            return Err("unknown encryption version".into());
        }
        if payload.len() < 132 || payload.len() > 87472 {
            return Err("invalid payload size".into());
        }
        let d = ark_net::crypto::b64_decode(payload).ok_or("invalid base64")?;
        if d.len() < 99 || d.len() > 65603 {
            return Err("invalid data size".into());
        }
        if d[0] != 2 {
            return Err(format!("unknown encryption version {}", d[0]));
        }
        let nonce: [u8; 32] = d[1..33].try_into().unwrap();
        let (ct, mac) = d[33..].split_at(d.len() - 33 - 32);
        let (ck, cn, hk) = message_keys(conv, &nonce);
        let mut mac_in = nonce.to_vec();
        mac_in.extend_from_slice(ct);
        if !ark_net::crypto::ct_eq(&hmac_sha256(&hk, &mac_in), mac) {
            return Err("invalid MAC".into());
        }
        let mut padded = ct.to_vec();
        chacha20(&ck, &cn, 0, &mut padded);
        let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
        if len == 0 || padded.len() != 2 + calc_padded_len(len) {
            return Err("invalid padding".into());
        }
        String::from_utf8(padded[2..2 + len].to_vec()).map_err(|_| "plaintext is not UTF-8".into())
    }
}

// ---------------------------------------------------------------- NIP-04

pub mod nip04 {
    use super::*;
    use ark_net::crypto::{b64, b64_decode, Aes};

    pub fn encrypt(sk: &[u8; 32], pk: &[u8; 32], text: &str) -> Result<String, String> {
        let key = ecdh_x(sk, pk).ok_or("invalid recipient public key")?;
        let iv: [u8; 16] = random_bytes(16).try_into().unwrap();
        let ct = Aes::new(&key).ok_or("aes key")?.cbc_encrypt(&iv, text.as_bytes());
        Ok(format!("{}?iv={}", b64(&ct), b64(&iv)))
    }

    pub fn decrypt(sk: &[u8; 32], pk: &[u8; 32], content: &str) -> Result<String, String> {
        let (ct, iv) = content.split_once("?iv=").ok_or("NIP-04 content without ?iv=")?;
        let iv: [u8; 16] = b64_decode(iv.trim()).and_then(|v| v.try_into().ok()).ok_or("bad NIP-04 iv")?;
        let ct = b64_decode(ct.trim()).ok_or("bad NIP-04 ciphertext")?;
        let key = ecdh_x(sk, pk).ok_or("invalid sender public key")?;
        let pt = Aes::new(&key).ok_or("aes key")?.cbc_decrypt(&iv, &ct).ok_or("NIP-04 decryption failed")?;
        // cbc_decrypt tolerates WeCom's 32-byte padding; NIP-04 is strict PKCS#7 (≤ 16).
        if ct.len() - pt.len() > 16 {
            return Err("NIP-04 decryption failed".into());
        }
        String::from_utf8(pt).map_err(|_| "NIP-04 plaintext is not UTF-8".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_net::crypto::{hex, hex_decode};

    fn h32(s: &str) -> [u8; 32] {
        hex_decode(s).unwrap().try_into().unwrap()
    }
    fn h64(s: &str) -> [u8; 64] {
        hex_decode(s).unwrap().try_into().unwrap()
    }

    // BIP-340 test-vectors.csv, indexes 0-3 (signing).
    const SIGN: [(&str, &str, &str, &str, &str); 4] = [
        ("0000000000000000000000000000000000000000000000000000000000000003", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
        ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "0000000000000000000000000000000000000000000000000000000000000001", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
        ("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
        ("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
    ];

    #[test]
    fn bip340_sign_vectors() {
        for (i, (sk, pk, aux, msg, sig)) in SIGN.iter().enumerate() {
            let sk = h32(sk);
            assert_eq!(hex(&xonly_pubkey(&sk).unwrap()), pk.to_lowercase(), "pubkey {i}");
            let s = schnorr_sign(&sk, &h32(msg), &h32(aux)).unwrap();
            assert_eq!(hex(&s), sig.to_lowercase(), "signature {i}");
            assert!(schnorr_verify(&h32(pk), &h32(msg), &s), "verify {i}");
        }
    }

    #[test]
    fn bip340_variable_length_messages() {
        let sk = h32("0340034003400340034003400340034003400340034003400340034003400340");
        let aux = [0u8; 32];
        let cases: [(&[u8], &str); 3] = [
            (b"", "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"),
            (&[0x11], "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF"),
            (&[0x99; 100], "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367"),
        ];
        for (msg, sig) in cases {
            assert_eq!(hex(&schnorr_sign(&sk, msg, &aux).unwrap()), sig.to_lowercase());
        }
    }

    #[test]
    fn bip340_verify_vectors() {
        let pk1 = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";
        let m1 = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";
        let cases = [
            (4, "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", true),
            (5, "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", m1, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
            (6, pk1, m1, "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", false),
            (7, pk1, m1, "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", false),
            (8, pk1, m1, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", false),
            (9, pk1, m1, "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", false),
            (10, pk1, m1, "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", false),
            (11, pk1, m1, "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
            (12, pk1, m1, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
            (13, pk1, m1, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", false),
            (14, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", m1, "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
        ];
        for (i, pk, msg, sig, ok) in cases {
            assert_eq!(schnorr_verify(&h32(pk), &h32(msg), &h64(sig)), ok, "vector {i}");
        }
    }

    #[test]
    fn keys_and_ecdh() {
        assert!(!valid_secret(&[0; 32]));
        assert!(!valid_secret(&to_be(&N.m)));
        assert!(valid_secret(&to_be(&sub_raw(&N.m, &[1, 0, 0, 0]).0)));
        let (a, b) = (random_secret(), random_secret());
        let (pa, pb) = (xonly_pubkey(&a).unwrap(), xonly_pubkey(&b).unwrap());
        assert_eq!(ecdh_x(&a, &pb), ecdh_x(&b, &pa), "ECDH is symmetric");
        let sig = sign(&a, b"hello").unwrap();
        assert!(schnorr_verify(&pa, b"hello", &sig) && !schnorr_verify(&pb, b"hello", &sig) && !schnorr_verify(&pa, b"hellO", &sig));
        // Field / scalar sanity: inverse and wraparound.
        let x = from_be(&h32("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
        assert_eq!(P.mul(&x, &P.inv(&x)), [1, 0, 0, 0]);
        assert_eq!(N.add(&sub_raw(&N.m, &[1, 0, 0, 0]).0, &[2, 0, 0, 0]), [1, 0, 0, 0]);
        assert_eq!(P.sub(&[0; 4], &[1, 0, 0, 0]), sub_raw(&P.m, &[1, 0, 0, 0]).0);
    }

    #[test]
    fn bech32_and_nip19() {
        // NIP-19 examples.
        let pk = h32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
        assert_eq!(npub(&pk), "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6");
        assert_eq!(nip19_decode("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6").unwrap(), Nip19::Npub(pk));
        let sk = h32("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa");
        assert_eq!(nsec(&sk), "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5");
        assert_eq!(parse_secret_key("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5").unwrap(), sk);
        assert_eq!(parse_secret_key(&hex(&sk).to_uppercase()).unwrap(), sk);
        let np = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
        match nip19_decode(np).unwrap() {
            Nip19::Nprofile { pubkey, relays } => {
                assert_eq!(pubkey, pk);
                assert_eq!(relays, vec!["wss://r.x.com".to_string(), "wss://djbas.sadkb.com".to_string()]);
                assert_eq!(nprofile(&pubkey, &relays), np, "round trip");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(parse_pubkey(&format!("nostr:{np}")).unwrap(), pk);
        let id = h32("46d731680add2990efe1cc619dc9b8014feeb23261ab9dee50e9d11814de5a2b");
        assert_eq!(nip19_decode(&note(&id)).unwrap(), Nip19::Note(id));
        assert!(nip19_decode("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7").is_err(), "checksum");
        assert!(nip19_decode("Npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6").is_err(), "mixed case");
        assert!(parse_secret_key("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6").is_err());
        assert!(parse_secret_key(&"f".repeat(64)).is_err(), "≥ n");
    }

    #[test]
    fn chacha20_rfc8439() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = hex_decode("000000000000004a00000000").unwrap().try_into().unwrap();
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20(&key, &nonce, 1, &mut data);
        assert_eq!(
            hex(&data),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        );
    }

    #[test]
    fn nip44_vectors() {
        for (sec1, pub2, conv) in [
            ("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268", "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133", "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"),
            ("a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e", "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800", "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b"),
            ("98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311", "aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1", "9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7"),
        ] {
            assert_eq!(hex(&nip44::conversation_key(&h32(sec1), &h32(pub2)).unwrap()), conv);
        }
        for (sec1, sec2, conv, nonce, pt, payload) in [
            ("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000002", "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d", "0000000000000000000000000000000000000000000000000000000000000001", "a", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"),
            ("0000000000000000000000000000000000000000000000000000000000000002", "0000000000000000000000000000000000000000000000000000000000000001", "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d", "f00000000000000000000000000000f00000000000000000000000000000000f", "🍕🫃", "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj"),
            ("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a", "4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d", "3e2b52a63be47d34fe0a80e34e73d436d6963bc8f39827f327057a9986c20a45", "b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b", "表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀", "ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7s7JqlCMJBAIIjfkpHReBPXeoMCyuClwgbT419jUWU1PwaNl4FEQYKCDKVJz+97Mp3K+Q2YGa77B6gpxB/lr1QgoqpDf7wDVrDmOqGoiPjWDqy8KzLueKDcm9BVP8xeTJIxs="),
        ] {
            let pub2 = xonly_pubkey(&h32(sec2)).unwrap();
            let ck = nip44::conversation_key(&h32(sec1), &pub2).unwrap();
            assert_eq!(hex(&ck), conv);
            assert_eq!(nip44::encrypt(&ck, pt, Some(h32(nonce))).unwrap(), payload);
            assert_eq!(nip44::decrypt(&ck, payload).unwrap(), pt);
        }
        for (len, padded) in [(16, 32), (32, 32), (33, 64), (257, 320), (65535, 65536)] {
            assert_eq!(nip44::calc_padded_len(len), padded);
        }
        let bad1 = "#Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJdU0MIDf06CUvEvdnr1cp1fiMtlM/GrE92xAc1K5odTpCzUB+mjXgbaqtntBUbTToSUoT0ovrlPwzGjyp";
        assert!(nip44::decrypt(&h32("ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642"), bad1).unwrap_err().contains("unknown encryption version"));
        let bad2 = "AK1AjUvoYW3IS7C/BGRUoqEC7ayTfDUgnEPNeWTF/reBZFaha6EAIRueE9D1B1RuoiuFScC0Q94yjIuxZD3JStQtE8JMNacWFs9rlYP+ZydtHhRucp+lxfdvFlaGV/sQlqZz";
        assert_eq!(nip44::decrypt(&h32("36f04e558af246352dcf73b692fbd3646a2207bd8abd4b1cd26b234db84d9481"), bad2).unwrap_err(), "unknown encryption version 0");
        // Tampered MAC.
        let ck = h32("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
        let p = nip44::encrypt(&ck, "hello", None).unwrap();
        let mut raw = ark_net::crypto::b64_decode(&p).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        assert_eq!(nip44::decrypt(&ck, &ark_net::crypto::b64(&raw)).unwrap_err(), "invalid MAC");
        assert!(nip44::encrypt(&ck, "", None).is_err());
    }

    #[test]
    fn nip04_round_trip() {
        let (a, b) = (random_secret(), random_secret());
        let (pa, pb) = (xonly_pubkey(&a).unwrap(), xonly_pubkey(&b).unwrap());
        let c = nip04::encrypt(&a, &pb, "秘密 message").unwrap();
        assert!(c.contains("?iv="));
        assert_eq!(nip04::decrypt(&b, &pa, &c).unwrap(), "秘密 message");
        assert!(nip04::decrypt(&b, &pb, &c).is_err() || nip04::decrypt(&b, &pb, &c).unwrap() != "秘密 message");
        assert!(nip04::decrypt(&b, &pa, "garbage").is_err());
    }
}
