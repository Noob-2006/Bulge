//! NIST P-256 scalar multiplication for HPKE DHKEM(P-256) (RFC 9180), which
//! MLS cipher suite 2 (DAVE) needs with *static* and *derived* private keys —
//! ring only does ECDH with ephemeral keys it generates itself. ECDSA stays in
//! ring. Field elements are 4×64-bit little-endian limbs in Montgomery form
//! (p ≡ -1 mod 2^64, so the Montgomery constant is 1); points use the complete
//! projective addition formulas for a = -3 (Renes–Costello–Batina 2015,
//! algorithm 4), so doubling and the identity need no special cases, and the
//! ladder selects with masks instead of branching on secret bits.

type U = [u64; 4];

const P: U = [u64::MAX, 0x0000_0000_FFFF_FFFF, 0, 0xFFFF_FFFF_0000_0001];
const N: U = [0xF3B9_CAC2_FC63_2551, 0xBCE6_FAAD_A717_9E84, u64::MAX, 0xFFFF_FFFF_0000_0000];
/// R² mod p (to enter Montgomery form).
const R2: U = [3, 0xFFFF_FFFB_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFE, 0x0000_0004_FFFF_FFFD];
const B: U = [0x3BCE_3C3E_27D2_604B, 0x651D_06B0_CC53_B0F6, 0xB3EB_BD55_7698_86BC, 0x5AC6_35D8_AA3A_93E7];
const GX: U = [0xF4A1_3945_D898_C296, 0x7703_7D81_2DEB_33A0, 0xF8BC_E6E5_63A4_40F2, 0x6B17_D1F2_E12C_4247];
const GY: U = [0xCBB6_4068_37BF_51F5, 0x2BCE_3357_6B31_5ECE, 0x8EE7_EB4A_7C0F_9E16, 0x4FE3_42E2_FE1A_7F9B];

fn from_be(b: &[u8]) -> U {
    let mut r = [0u64; 4];
    for (i, l) in r.iter_mut().enumerate() {
        *l = u64::from_be_bytes(b[24 - 8 * i..32 - 8 * i].try_into().unwrap());
    }
    r
}

fn to_be(a: &U) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, l) in a.iter().enumerate() {
        o[24 - 8 * i..32 - 8 * i].copy_from_slice(&l.to_be_bytes());
    }
    o
}

fn sub_raw(a: &U, b: &U) -> (U, u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let t = (a[i] as u128).wrapping_sub(b[i] as u128 + borrow as u128);
        r[i] = t as u64;
        borrow = (t >> 127) as u64;
    }
    (r, borrow)
}

fn lt(a: &U, b: &U) -> bool {
    sub_raw(a, b).1 == 1
}

fn sel(mask: u64, a: &U, b: &U) -> U {
    std::array::from_fn(|i| (a[i] & mask) | (b[i] & !mask))
}

/// a + b mod p (inputs < p).
fn add(a: &U, b: &U) -> U {
    let mut r = [0u64; 4];
    let mut c = 0u128;
    for i in 0..4 {
        c += a[i] as u128 + b[i] as u128;
        r[i] = c as u64;
        c >>= 64;
    }
    let (t, borrow) = sub_raw(&r, &P);
    // Subtract p when the sum overflowed 2^256 or is ≥ p.
    sel(0u64.wrapping_sub((c as u64) | (borrow ^ 1)), &t, &r)
}

fn sub(a: &U, b: &U) -> U {
    let (r, borrow) = sub_raw(a, b);
    let mut o = [0u64; 4];
    let mask = 0u64.wrapping_sub(borrow);
    let mut c = 0u128;
    for i in 0..4 {
        c += r[i] as u128 + (P[i] & mask) as u128;
        o[i] = c as u64;
        c >>= 64;
    }
    o
}

/// Montgomery product a·b·2^-256 mod p (CIOS; -p^-1 mod 2^64 = 1).
fn mul(a: &U, b: &U) -> U {
    let mut t = [0u64; 6];
    for &ai in a {
        let mut c = 0u128;
        for j in 0..4 {
            let s = t[j] as u128 + ai as u128 * b[j] as u128 + c;
            t[j] = s as u64;
            c = s >> 64;
        }
        let s = t[4] as u128 + c;
        t[4] = s as u64;
        t[5] = (s >> 64) as u64;
        let m = t[0];
        let mut c = (t[0] as u128 + m as u128 * P[0] as u128) >> 64;
        for j in 1..4 {
            let s = t[j] as u128 + m as u128 * P[j] as u128 + c;
            t[j - 1] = s as u64;
            c = s >> 64;
        }
        let s = t[4] as u128 + c;
        t[3] = s as u64;
        t[4] = t[5] + (s >> 64) as u64;
        t[5] = 0;
    }
    let r = [t[0], t[1], t[2], t[3]];
    let (d, borrow) = sub_raw(&r, &P);
    sel(0u64.wrapping_sub(t[4] | (borrow ^ 1)), &d, &r)
}

fn to_mont(a: &U) -> U {
    mul(a, &R2)
}

fn from_mont(a: &U) -> U {
    mul(a, &[1, 0, 0, 0])
}

/// a^(p-2) (Fermat inverse); the exponent is public.
fn inv(a: &U) -> U {
    let e = sub_raw(&P, &[2, 0, 0, 0]).0;
    let mut r = to_mont(&[1, 0, 0, 0]);
    for i in (0..256).rev() {
        r = mul(&r, &r);
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            r = mul(&r, a);
        }
    }
    r
}

#[derive(Clone, Copy)]
struct Pt {
    x: U,
    y: U,
    z: U,
}

impl Pt {
    fn identity() -> Pt {
        Pt { x: [0; 4], y: to_mont(&[1, 0, 0, 0]), z: [0; 4] }
    }

    /// RCB 2015 algorithm 4 (complete, a = -3); all values in Montgomery form.
    fn add(&self, q: &Pt) -> Pt {
        let b = to_mont(&B);
        let (x1, y1, z1, x2, y2, z2) = (&self.x, &self.y, &self.z, &q.x, &q.y, &q.z);
        let mut t0 = mul(x1, x2);
        let mut t1 = mul(y1, y2);
        let mut t2 = mul(z1, z2);
        let mut t3 = add(x1, y1);
        let mut t4 = add(x2, y2);
        t3 = mul(&t3, &t4);
        t4 = add(&t0, &t1);
        t3 = sub(&t3, &t4);
        t4 = add(y1, z1);
        let mut x3 = add(y2, z2);
        t4 = mul(&t4, &x3);
        x3 = add(&t1, &t2);
        t4 = sub(&t4, &x3);
        x3 = add(x1, z1);
        let mut y3 = add(x2, z2);
        x3 = mul(&x3, &y3);
        y3 = add(&t0, &t2);
        y3 = sub(&x3, &y3);
        let mut z3 = mul(&b, &t2);
        x3 = sub(&y3, &z3);
        z3 = add(&x3, &x3);
        x3 = add(&x3, &z3);
        z3 = sub(&t1, &x3);
        x3 = add(&t1, &x3);
        y3 = mul(&b, &y3);
        t1 = add(&t2, &t2);
        t2 = add(&t1, &t2);
        y3 = sub(&y3, &t2);
        y3 = sub(&y3, &t0);
        t1 = add(&y3, &y3);
        y3 = add(&t1, &y3);
        t1 = add(&t0, &t0);
        t0 = add(&t1, &t0);
        t0 = sub(&t0, &t2);
        t1 = mul(&t4, &y3);
        t2 = mul(&t0, &y3);
        y3 = mul(&x3, &z3);
        y3 = add(&y3, &t2);
        x3 = mul(&t3, &x3);
        x3 = sub(&x3, &t1);
        z3 = mul(&t4, &z3);
        t1 = mul(&t3, &t0);
        z3 = add(&z3, &t1);
        Pt { x: x3, y: y3, z: z3 }
    }

    fn sel(mask: u64, a: &Pt, b: &Pt) -> Pt {
        Pt { x: sel(mask, &a.x, &b.x), y: sel(mask, &a.y, &b.y), z: sel(mask, &a.z, &b.z) }
    }

    /// Double-and-add, always both operations, masked select per bit.
    fn mul_scalar(&self, k: &U) -> Pt {
        let mut r = Pt::identity();
        for i in (0..256).rev() {
            r = r.add(&r);
            let t = r.add(self);
            r = Pt::sel(0u64.wrapping_sub((k[i / 64] >> (i % 64)) & 1), &t, &r);
        }
        r
    }

    /// Uncompressed SEC1 (0x04 ‖ X ‖ Y); None for the identity.
    fn encode(&self) -> Option<[u8; 65]> {
        if self.z == [0; 4] {
            return None;
        }
        let zi = inv(&self.z);
        let (x, y) = (from_mont(&mul(&self.x, &zi)), from_mont(&mul(&self.y, &zi)));
        let mut o = [0u8; 65];
        o[0] = 4;
        o[1..33].copy_from_slice(&to_be(&x));
        o[33..].copy_from_slice(&to_be(&y));
        Some(o)
    }

    /// Parse and validate an uncompressed point (on the curve, coordinates < p).
    fn decode(b: &[u8]) -> Option<Pt> {
        if b.len() != 65 || b[0] != 4 {
            return None;
        }
        let (x, y) = (from_be(&b[1..33]), from_be(&b[33..]));
        if !lt(&x, &P) || !lt(&y, &P) {
            return None;
        }
        let (xm, ym) = (to_mont(&x), to_mont(&y));
        // y² = x³ - 3x + b
        let rhs = add(&sub(&mul(&mul(&xm, &xm), &xm), &add(&add(&xm, &xm), &xm)), &to_mont(&B));
        (mul(&ym, &ym) == rhs).then(|| Pt { x: xm, y: ym, z: to_mont(&[1, 0, 0, 0]) })
    }
}

fn generator() -> Pt {
    Pt { x: to_mont(&GX), y: to_mont(&GY), z: to_mont(&[1, 0, 0, 0]) }
}

/// A valid private scalar: 0 < k < n.
pub fn valid_scalar(sk: &[u8]) -> bool {
    sk.len() == 32 && {
        let k = from_be(sk);
        k != [0; 4] && lt(&k, &N)
    }
}

/// sk·G as uncompressed SEC1 bytes.
pub fn public_key(sk: &[u8]) -> Option<[u8; 65]> {
    valid_scalar(sk).then(|| generator().mul_scalar(&from_be(sk)).encode()).flatten()
}

/// ECDH shared secret: the x coordinate of sk·Pk (RFC 9180 §7.1.1).
pub fn ecdh(sk: &[u8], pk: &[u8]) -> Option<[u8; 32]> {
    if !valid_scalar(sk) {
        return None;
    }
    let p = Pt::decode(pk)?.mul_scalar(&from_be(sk)).encode()?;
    Some(p[1..33].try_into().unwrap())
}

pub fn valid_point(pk: &[u8]) -> bool {
    Pt::decode(pk).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_net::crypto::{hex, hex_decode};
    use ring::agreement;
    use ring::rand::SystemRandom;

    #[test]
    fn known_multiples_and_validation() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let g = public_key(&one).unwrap();
        assert_eq!(hex(&g[1..33]), "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        let mut two = [0u8; 32];
        two[31] = 2;
        let g2 = public_key(&two).unwrap();
        assert_eq!(hex(&g2[1..33]), "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");
        assert_eq!(hex(&g2[33..]), "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
        // (n-1)·G = -G.
        let nm1 = to_be(&sub_raw(&N, &[1, 0, 0, 0]).0);
        let neg = public_key(&nm1).unwrap();
        assert_eq!(neg[1..33], g[1..33]);
        assert_eq!(to_be(&sub_raw(&P, &from_be(&g[33..])).0), neg[33..]);
        assert!(!valid_scalar(&[0u8; 32]) && !valid_scalar(&to_be(&N)) && valid_scalar(&nm1));
        assert!(valid_point(&g2));
        let mut bad = g2;
        bad[64] ^= 1;
        assert!(!valid_point(&bad) && ecdh(&two, &bad).is_none());
    }

    #[test]
    fn ecdh_agrees_with_ring() {
        let rng = SystemRandom::new();
        for _ in 0..4 {
            let theirs = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            let their_pub = theirs.compute_public_key().unwrap();
            let sk = seagent_net::crypto::random_bytes(32);
            let mine = public_key(&sk).unwrap();
            let ours = ecdh(&sk, their_pub.as_ref()).unwrap();
            let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, mine.to_vec());
            let got = agreement::agree_ephemeral(theirs, &peer, |k| k.to_vec()).unwrap();
            assert_eq!(got, ours);
        }
        // RFC 9180 A.3.1 (DHKEM(P-256)): skRm → pkRm.
        let sk = hex_decode("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2").unwrap();
        assert_eq!(hex(&public_key(&sk).unwrap()), "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
    }
}
