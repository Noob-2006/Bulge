//! QR Code encoder for WhatsApp pairing payloads (`whatsapp_login`): byte mode, level M,
//! versions 1–20 (up to 666 bytes; Baileys payloads are ~240). Derived from ark's own
//! `ark-app/src/qr.rs` (versions 1–10) with the ISO/IEC 18004 tables extended, plus a PNG
//! writer (stored deflate) for the `data:image/png;base64,…` URL OpenClaw returns.

/// Per version (1-based): EC codewords per block and the block layout `(count, data codewords)`.
const BLOCKS_M: [(usize, &[(usize, usize)]); 20] = [
    (10, &[(1, 16)]),
    (16, &[(1, 28)]),
    (26, &[(1, 44)]),
    (18, &[(2, 32)]),
    (24, &[(2, 43)]),
    (16, &[(4, 27)]),
    (18, &[(4, 31)]),
    (22, &[(2, 38), (2, 39)]),
    (22, &[(3, 36), (2, 37)]),
    (26, &[(4, 43), (1, 44)]),
    (30, &[(1, 50), (4, 51)]),
    (22, &[(6, 36), (2, 37)]),
    (22, &[(8, 37), (1, 38)]),
    (24, &[(4, 40), (5, 41)]),
    (24, &[(5, 41), (5, 42)]),
    (28, &[(7, 45), (3, 46)]),
    (28, &[(10, 46), (1, 47)]),
    (26, &[(9, 43), (4, 44)]),
    (26, &[(3, 44), (11, 45)]),
    (26, &[(3, 41), (13, 42)]),
];
const ALIGN: [&[usize]; 20] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
    &[6, 30, 54],
    &[6, 32, 58],
    &[6, 34, 62],
    &[6, 26, 46, 66],
    &[6, 26, 48, 70],
    &[6, 26, 50, 74],
    &[6, 30, 54, 78],
    &[6, 30, 56, 82],
    &[6, 30, 58, 86],
    &[6, 34, 62, 90],
];
const MAX_VERSION: usize = 20;

pub struct Qr {
    /// Symbol version (1–20); read by the encoder parity tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub version: usize,
    pub size: usize,
    /// Row-major, true = dark.
    modules: Vec<bool>,
}

fn data_capacity(v: usize) -> usize {
    BLOCKS_M[v - 1].1.iter().map(|(n, d)| n * d).sum()
}

fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u16 = 0;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * 0x11d);
        z ^= ((y as u16 >> i) & 1) * x as u16;
    }
    z as u8
}

fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut r = vec![0u8; degree];
    r[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            r[j] = gf_mul(r[j], root);
            if j + 1 < degree {
                r[j] ^= r[j + 1];
            }
        }
        root = gf_mul(root, 2);
    }
    r
}

/// Reed–Solomon EC codewords for `data`.
fn rs_remainder(data: &[u8], degree: usize) -> Vec<u8> {
    let div = rs_divisor(degree);
    let mut r = vec![0u8; degree];
    for b in data {
        let f = b ^ r[0];
        r.remove(0);
        r.push(0);
        for (x, d) in r.iter_mut().zip(&div) {
            *x ^= gf_mul(*d, f);
        }
    }
    r
}

/// 15-bit format word for level M and `mask`.
fn format_bits(mask: u8) -> u32 {
    let data = mask as u32; // level M = 00
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

/// 18-bit version word (versions ≥ 7).
fn version_bits(v: usize) -> u32 {
    let mut rem = v as u32;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
    }
    ((v as u32) << 12) | rem
}

fn mask_bit(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y).is_multiple_of(2),
        1 => y.is_multiple_of(2),
        2 => x.is_multiple_of(3),
        3 => (x + y).is_multiple_of(3),
        4 => (x / 3 + y / 2).is_multiple_of(2),
        5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3).is_multiple_of(2),
        _ => ((x + y) % 2 + x * y % 3).is_multiple_of(2),
    }
}

struct Grid {
    size: usize,
    m: Vec<bool>,
    func: Vec<bool>,
}

impl Grid {
    fn set(&mut self, x: usize, y: usize, dark: bool) {
        self.m[y * self.size + x] = dark;
        self.func[y * self.size + x] = true;
    }
    fn finder(&mut self, cx: isize, cy: isize) {
        for dy in -4..=4isize {
            for dx in -4..=4isize {
                let (x, y) = (cx + dx, cy + dy);
                if x >= 0 && y >= 0 && (x as usize) < self.size && (y as usize) < self.size {
                    let d = dx.abs().max(dy.abs());
                    self.set(x as usize, y as usize, d != 2 && d != 4);
                }
            }
        }
    }
    fn format(&mut self, mask: u8) {
        let bits = format_bits(mask);
        let b = |i: u32| (bits >> i) & 1 != 0;
        let n = self.size;
        for i in 0..6 {
            self.set(8, i, b(i as u32));
        }
        self.set(8, 7, b(6));
        self.set(8, 8, b(7));
        self.set(7, 8, b(8));
        for i in 9..15 {
            self.set(14 - i, 8, b(i as u32));
        }
        for i in 0..8 {
            self.set(n - 1 - i, 8, b(i as u32));
        }
        for i in 8..15 {
            self.set(8, n - 15 + i, b(i as u32));
        }
        self.set(8, n - 8, true); // dark module
    }
}

impl Qr {
    /// Encode `data`; `None` when it does not fit version 20-M (666 bytes).
    pub fn encode(data: &[u8]) -> Option<Qr> {
        Qr::encode_masked(data, None)
    }

    /// `mask` forces a mask pattern (tests compare against reference encoders).
    pub fn encode_masked(data: &[u8], mask: Option<u8>) -> Option<Qr> {
        let v = (1..=MAX_VERSION).find(|&v| 4 + if v < 10 { 8 } else { 16 } + data.len() * 8 <= data_capacity(v) * 8)?;
        let cap = data_capacity(v);
        let mut bits: Vec<bool> = Vec::with_capacity(cap * 8);
        let push = |val: u32, n: usize, bits: &mut Vec<bool>| (0..n).rev().for_each(|i| bits.push((val >> i) & 1 != 0));
        push(0b0100, 4, &mut bits);
        push(data.len() as u32, if v < 10 { 8 } else { 16 }, &mut bits);
        for b in data {
            push(*b as u32, 8, &mut bits);
        }
        let term = (cap * 8 - bits.len()).min(4);
        push(0, term, &mut bits);
        while !bits.len().is_multiple_of(8) {
            bits.push(false);
        }
        let mut words: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |a, b| (a << 1) | *b as u8)).collect();
        for pad in [0xec, 0x11].iter().cycle() {
            if words.len() >= cap {
                break;
            }
            words.push(*pad);
        }
        // Split into blocks, add EC, interleave.
        let (ec, layout) = BLOCKS_M[v - 1];
        let mut blocks: Vec<(&[u8], Vec<u8>)> = Vec::new();
        let mut off = 0;
        for (n, len) in layout {
            for _ in 0..*n {
                let d = &words[off..off + len];
                blocks.push((d, rs_remainder(d, ec)));
                off += len;
            }
        }
        let maxd = blocks.iter().map(|b| b.0.len()).max().unwrap_or(0);
        let mut all = Vec::new();
        for i in 0..maxd {
            all.extend(blocks.iter().filter_map(|b| b.0.get(i)));
        }
        for i in 0..ec {
            all.extend(blocks.iter().map(|b| b.1[i]));
        }
        let size = 17 + 4 * v;
        let mut g = Grid { size, m: vec![false; size * size], func: vec![false; size * size] };
        for i in 0..size {
            g.set(6, i, i % 2 == 0);
            g.set(i, 6, i % 2 == 0);
        }
        g.finder(3, 3);
        g.finder(size as isize - 4, 3);
        g.finder(3, size as isize - 4);
        let al = ALIGN[v - 1];
        for (i, &ax) in al.iter().enumerate() {
            for (j, &ay) in al.iter().enumerate() {
                let corner = (i == 0 && j == 0) || (i == 0 && j + 1 == al.len()) || (i + 1 == al.len() && j == 0);
                if !corner {
                    for dy in -2..=2isize {
                        for dx in -2..=2isize {
                            g.set((ax as isize + dx) as usize, (ay as isize + dy) as usize, dx.abs().max(dy.abs()) != 1);
                        }
                    }
                }
            }
        }
        g.format(0); // reserve the format area
        if v >= 7 {
            let vb = version_bits(v);
            for i in 0..18 {
                let dark = (vb >> i) & 1 != 0;
                let (a, b) = (size - 11 + i % 3, i / 3);
                g.set(a, b, dark);
                g.set(b, a, dark);
            }
        }
        // Zig-zag codeword placement.
        let mut i = 0;
        let mut right = size as isize - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..size {
                for j in 0..2 {
                    let x = (right - j) as usize;
                    let up = (right + 1) & 2 == 0;
                    let y = if up { size - 1 - vert } else { vert };
                    if !g.func[y * size + x] && i < all.len() * 8 {
                        g.m[y * size + x] = (all[i >> 3] >> (7 - (i & 7))) & 1 != 0;
                        i += 1;
                    }
                }
            }
            right -= 2;
        }
        // Pick the mask with the lowest penalty.
        let base = g.m.clone();
        let mut best = (u32::MAX, mask.unwrap_or(0));
        for mask in (0..8u8).filter(|_| mask.is_none()) {
            g.m.clone_from(&base);
            apply_mask(&mut g, mask);
            g.format(mask);
            let p = penalty(&g.m, size);
            if p < best.0 {
                best = (p, mask);
            }
        }
        g.m = base;
        apply_mask(&mut g, best.1);
        g.format(best.1);
        Some(Qr { version: v, size, modules: g.m })
    }

    pub fn dark(&self, x: usize, y: usize) -> bool {
        x < self.size && y < self.size && self.modules[y * self.size + x]
    }

    /// Two module rows per text line. Light modules are drawn (█▀▄) so the code reads
    /// correctly on dark terminals; `quiet` light modules surround it.
    pub fn render(&self, quiet: usize) -> String {
        let n = self.size + 2 * quiet;
        let light = |x: usize, y: usize| x < quiet || y < quiet || x >= quiet + self.size || y >= quiet + self.size || !self.dark(x - quiet, y - quiet);
        let mut out = String::new();
        for y in (0..n).step_by(2) {
            for x in 0..n {
                let (t, b) = (light(x, y), y + 1 >= n || light(x, y + 1));
                out.push(match (t, b) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                });
            }
            out.push('\n');
        }
        out
    }
}

fn apply_mask(g: &mut Grid, mask: u8) {
    for y in 0..g.size {
        for x in 0..g.size {
            if !g.func[y * g.size + x] && mask_bit(mask, x, y) {
                g.m[y * g.size + x] ^= true;
            }
        }
    }
}

fn penalty(m: &[bool], n: usize) -> u32 {
    let at = |x: usize, y: usize| m[y * n + x];
    let mut p = 0u32;
    let finder: [bool; 11] = [true, false, true, true, true, false, true, false, false, false, false];
    for horiz in [true, false] {
        for a in 0..n {
            let line: Vec<bool> = (0..n).map(|b| if horiz { at(b, a) } else { at(a, b) }).collect();
            let mut run = 1;
            for b in 1..=n {
                if b < n && line[b] == line[b - 1] {
                    run += 1;
                } else {
                    if run >= 5 {
                        p += 3 + (run - 5) as u32;
                    }
                    run = 1;
                }
            }
            for w in line.windows(11) {
                if w == finder || w.iter().rev().eq(finder.iter()) {
                    p += 40;
                }
            }
        }
    }
    for y in 0..n - 1 {
        for x in 0..n - 1 {
            let c = at(x, y);
            if c == at(x + 1, y) && c == at(x, y + 1) && c == at(x + 1, y + 1) {
                p += 3;
            }
        }
    }
    let dark = m.iter().filter(|d| **d).count() as i64;
    let total = (n * n) as i64;
    let k = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
    p + (k.max(0) as u32) * 10
}


impl Qr {
    /// Row-major modules as '1'/'0' lines (test fixtures).
    #[cfg(test)]
    pub fn rows(&self) -> String {
        (0..self.size).map(|y| (0..self.size).map(|x| if self.dark(x, y) { '1' } else { '0' }).collect::<String>()).collect::<Vec<_>>().join("\n")
    }

    /// 1-bit grayscale PNG, `scale` pixels per module and `quiet` light modules of margin.
    pub fn png(&self, scale: usize, quiet: usize) -> Vec<u8> {
        let n = (self.size + 2 * quiet) * scale;
        let row = n.div_ceil(8);
        let mut raw = Vec::with_capacity((row + 1) * n);
        for py in 0..n {
            raw.push(0); // filter: none
            let mut bytes = vec![0u8; row];
            for px in 0..n {
                let (x, y) = (px / scale, py / scale);
                let dark = x >= quiet && y >= quiet && self.dark(x - quiet, y - quiet);
                if !dark {
                    bytes[px / 8] |= 0x80 >> (px % 8);
                }
            }
            raw.extend_from_slice(&bytes);
        }
        let mut z = vec![0x78, 0x01];
        let chunks: Vec<&[u8]> = raw.chunks(65535).collect();
        for (i, c) in chunks.iter().enumerate() {
            z.push(u8::from(i + 1 == chunks.len()));
            z.extend_from_slice(&(c.len() as u16).to_le_bytes());
            z.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
            z.extend_from_slice(c);
        }
        z.extend_from_slice(&adler32(&raw).to_be_bytes());
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&(n as u32).to_be_bytes());
        ihdr.extend_from_slice(&(n as u32).to_be_bytes());
        ihdr.extend_from_slice(&[1, 0, 0, 0, 0]);
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        for (ty, data) in [(&b"IHDR"[..], &ihdr[..]), (b"IDAT", &z[..]), (b"IEND", &[][..])] {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let start = out.len();
            out.extend_from_slice(ty);
            out.extend_from_slice(data);
            let crc = crc32(&out[start..]);
            out.extend_from_slice(&crc.to_be_bytes());
        }
        out
    }

    /// PNG data URL at the largest scale (≤ 6 px/module) that stays under 16 000 characters,
    /// the bound `whatsapp_login` accepts back as `currentQrDataUrl`.
    pub fn png_data_url(&self) -> String {
        let url = |s| format!("data:image/png;base64,{}", ark_core::tool::base64_encode(&self.png(s, 4)));
        (2..=6).rev().map(url).find(|u| u.len() <= 16_000).unwrap_or_else(|| url(1))
    }
}

fn adler32(d: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for x in d {
        a = (a + *x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn crc32(d: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for x in d {
        c ^= *x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| 33 + ((i * 7) % 90) as u8).collect()
    }

    fn sha(s: &str) -> String {
        ark_net::crypto::hex(&ark_net::crypto::sha256(s.as_bytes()))
    }

    /// Matrices match the `qrcode` npm package (OpenClaw's encoder) for fixed masks.
    #[test]
    fn matches_reference_encoder_up_to_v20() {
        for (len, mask, version, digest) in [
            (60, 1, 4, "ef8a00e678c67fc6e533be64e0de6dcbca26a448e33c43ad1b9159955b2365c3"),
            (240, 3, 11, "6b1bd83ec73e8db9c83c1a6d7d2886d7cc7f22c0777fdff040dc6d58de55caf5"),
            (330, 5, 13, "dd4ceab69b78edded61cc672df30774adca5b1024523de10de0c6a5255532340"),
        ] {
            let q = Qr::encode_masked(&payload(len), Some(mask)).unwrap();
            assert_eq!(q.version, version, "len {len}");
            assert_eq!(sha(&q.rows()), digest, "len {len}");
        }
        assert!(Qr::encode(&payload(667)).is_none());
        let png = Qr::encode(b"2@abc").unwrap().png(2, 1);
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n") && png.ends_with(&crc32(b"IEND").to_be_bytes()));
        assert!(Qr::encode(b"x").unwrap().png_data_url().starts_with("data:image/png;base64,iVBOR"));
        for len in [240, 330, 600] {
            assert!(Qr::encode(&payload(len)).unwrap().png_data_url().len() <= 16_000);
        }
    }
}
