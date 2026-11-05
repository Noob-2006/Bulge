//! scrypt (RFC 7914) on top of ring's PBKDF2-HMAC-SHA256: Salsa20/8 core,
//! BlockMix, ROMix. Used for DAVE pairwise verification fingerprints.

use std::num::NonZeroU32;

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            x[$b] ^= x[$a].wrapping_add(x[$d]).rotate_left(7);
            x[$c] ^= x[$b].wrapping_add(x[$a]).rotate_left(9);
            x[$d] ^= x[$c].wrapping_add(x[$b]).rotate_left(13);
            x[$a] ^= x[$d].wrapping_add(x[$c]).rotate_left(18);
        };
    }
    for _ in 0..4 {
        qr!(0, 4, 8, 12);
        qr!(5, 9, 13, 1);
        qr!(10, 14, 2, 6);
        qr!(15, 3, 7, 11);
        qr!(0, 1, 2, 3);
        qr!(5, 6, 7, 4);
        qr!(10, 11, 8, 9);
        qr!(15, 12, 13, 14);
    }
    for (o, v) in b.iter_mut().zip(x) {
        *o = o.wrapping_add(v);
    }
}

/// BlockMix_{Salsa20/8, r}: `b` is 2r 16-word blocks; `y` is scratch of the same size.
fn block_mix(b: &mut [u32], y: &mut [u32], r: usize) {
    let mut x: [u32; 16] = b[(2 * r - 1) * 16..].try_into().unwrap();
    for i in 0..2 * r {
        for (k, v) in x.iter_mut().enumerate() {
            *v ^= b[i * 16 + k];
        }
        salsa20_8(&mut x);
        // Even blocks first, then odd.
        let at = (i / 2 + (i % 2) * r) * 16;
        y[at..at + 16].copy_from_slice(&x);
    }
    b.copy_from_slice(y);
}

fn ro_mix(block: &mut [u8], n: usize, r: usize) {
    let words = 32 * r;
    let mut x: Vec<u32> = block.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
    let mut v = vec![0u32; words * n];
    let mut y = vec![0u32; words];
    for i in 0..n {
        v[i * words..(i + 1) * words].copy_from_slice(&x);
        block_mix(&mut x, &mut y, r);
    }
    for _ in 0..n {
        let j = (x[(2 * r - 1) * 16] as usize) & (n - 1);
        for (a, b) in x.iter_mut().zip(&v[j * words..(j + 1) * words]) {
            *a ^= b;
        }
        block_mix(&mut x, &mut y, r);
    }
    for (c, w) in block.as_chunks_mut::<4>().0.iter_mut().zip(x) {
        *c = w.to_le_bytes();
    }
}

/// scrypt(P, S, N, r, p, dkLen). `n` must be a power of two > 1.
pub fn scrypt(pass: &[u8], salt: &[u8], n: usize, r: usize, p: usize, dk_len: usize) -> Vec<u8> {
    assert!(n > 1 && n.is_power_of_two() && r > 0 && p > 0, "invalid scrypt parameters");
    let one = NonZeroU32::new(1).unwrap();
    let mut b = vec![0u8; p * 128 * r];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, one, salt, pass, &mut b);
    for chunk in b.chunks_exact_mut(128 * r) {
        ro_mix(chunk, n, r);
    }
    let mut out = vec![0u8; dk_len];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, one, &b, pass, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_net::crypto::{hex, hex_decode};

    #[test]
    fn rfc7914_salsa_core_and_vectors() {
        // §8: Salsa20/8 core.
        let input = hex_decode("7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1dee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e").unwrap();
        let mut w: [u32; 16] = std::array::from_fn(|i| u32::from_le_bytes(input[i * 4..i * 4 + 4].try_into().unwrap()));
        salsa20_8(&mut w);
        let out: Vec<u8> = w.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&out), "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81");
        // §12 (the N = 2^20 vector needs 1 GiB and is left out).
        assert_eq!(hex(&scrypt(b"", b"", 16, 1, 1, 64)), "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
        assert_eq!(hex(&scrypt(b"password", b"NaCl", 1024, 8, 16, 64)), "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
        assert_eq!(hex(&scrypt(b"pleaseletmein", b"SodiumChloride", 16384, 8, 1, 64)), "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
    }
}
