//! A small QR Code encoder (ISO/IEC 18004): byte mode, error correction level M,
//! versions 1–10 (up to 213 bytes), rendered for terminals with Unicode half blocks.
//! Used to show node setup codes (`ark nodes setup-code`).

/// Per version (1-based): EC codewords per block and the block layout `(count, data codewords)`.
const BLOCKS_M: [(usize, &[(usize, usize)]); 10] = [
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
];
const ALIGN: [&[usize]; 10] = [&[], &[6, 18], &[6, 22], &[6, 26], &[6, 30], &[6, 34], &[6, 22, 38], &[6, 24, 42], &[6, 26, 46], &[6, 28, 50]];

pub struct Qr {
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
pub fn rs_remainder(data: &[u8], degree: usize) -> Vec<u8> {
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
pub fn format_bits(mask: u8) -> u32 {
    let data = mask as u32; // level M = 00
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

/// 18-bit version word (versions ≥ 7).
pub fn version_bits(v: usize) -> u32 {
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
    /// Encode `data`; `None` when it does not fit version 10-M (213 bytes).
    pub fn encode(data: &[u8]) -> Option<Qr> {
        let v = (1..=10).find(|&v| 4 + if v < 10 { 8 } else { 16 } + data.len() * 8 <= data_capacity(v) * 8)?;
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
        let mut best = (u32::MAX, 0u8);
        for mask in 0..8u8 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // ISO 18004 / thonky.com "HELLO WORLD" 1-M EC codewords.
        let data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
        assert_eq!(rs_remainder(&data, 10), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
        assert_eq!(format_bits(0), 0b101010000010010);
        assert_eq!(format_bits(5), 0b100000011001110);
        assert_eq!(format_bits(7), 0b100101010100000);
        assert_eq!(version_bits(7), 0b000111110010010100);
        assert_eq!(version_bits(10), 0b001010010011010011);
    }

    /// Read the symbol back (format word, codewords, RS syndromes, payload).
    fn decode(q: &Qr) -> Vec<u8> {
        let n = q.size;
        let fmt = (0..6).map(|i| q.dark(8, i)).chain([q.dark(8, 7), q.dark(8, 8), q.dark(7, 8)]).chain((9..15).map(|i| q.dark(14 - i, 8))).enumerate().fold(0u32, |a, (i, b)| a | (b as u32) << i);
        let mask = (0..8u8).find(|m| format_bits(*m) == fmt).expect("valid format word");
        let second = (0..8).map(|i| q.dark(n - 1 - i, 8)).chain((8..15).map(|i| q.dark(8, n - 15 + i))).enumerate().fold(0u32, |a, (i, b)| a | (b as u32) << i);
        assert_eq!(fmt, second, "both format copies agree");
        // Rebuild the function-pattern map with an empty encode of the same version.
        let v = q.version;
        let mut g = Grid { size: n, m: vec![false; n * n], func: vec![false; n * n] };
        // Same function layout as `encode` (timing, finders, alignment, format, version).
        for i in 0..n {
            g.set(6, i, false);
            g.set(i, 6, false);
        }
        g.finder(3, 3);
        g.finder(n as isize - 4, 3);
        g.finder(3, n as isize - 4);
        let al = ALIGN[v - 1];
        for (i, &ax) in al.iter().enumerate() {
            for (j, &ay) in al.iter().enumerate() {
                if !((i == 0 && j == 0) || (i == 0 && j + 1 == al.len()) || (i + 1 == al.len() && j == 0)) {
                    for dy in -2..=2isize {
                        for dx in -2..=2isize {
                            g.set((ax as isize + dx) as usize, (ay as isize + dy) as usize, false);
                        }
                    }
                }
            }
        }
        g.format(0);
        if v >= 7 {
            for i in 0..18 {
                g.set(n - 11 + i % 3, i / 3, false);
                g.set(i / 3, n - 11 + i % 3, false);
            }
        }
        let mut bits = Vec::new();
        let mut right = n as isize - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..n {
                for j in 0..2 {
                    let x = (right - j) as usize;
                    let y = if (right + 1) & 2 == 0 { n - 1 - vert } else { vert };
                    if !g.func[y * n + x] {
                        bits.push(q.dark(x, y) ^ mask_bit(mask, x, y));
                    }
                }
            }
            right -= 2;
        }
        let words: Vec<u8> = bits.chunks(8).filter(|c| c.len() == 8).map(|c| c.iter().fold(0u8, |a, b| (a << 1) | *b as u8)).collect();
        let (ec, layout) = BLOCKS_M[v - 1];
        let lens: Vec<usize> = layout.iter().flat_map(|(c, d)| std::iter::repeat_n(*d, *c)).collect();
        let nb = lens.len();
        let mut blocks: Vec<Vec<u8>> = vec![vec![]; nb];
        let mut k = 0;
        for i in 0..*lens.iter().max().unwrap() {
            for (b, l) in lens.iter().enumerate() {
                if i < *l {
                    blocks[b].push(words[k]);
                    k += 1;
                }
            }
        }
        let mut ecs: Vec<Vec<u8>> = vec![vec![]; nb];
        for _ in 0..ec {
            for e in ecs.iter_mut() {
                e.push(words[k]);
                k += 1;
            }
        }
        for (d, e) in blocks.iter().zip(&ecs) {
            assert_eq!(&rs_remainder(d, ec), e, "RS check");
        }
        let data: Vec<u8> = blocks.concat();
        assert_eq!(data[0] >> 4, 0b0100, "byte mode");
        let (len, start) = if v < 10 { ((((data[0] & 0xf) as usize) << 4) | (data[1] >> 4) as usize, 12) } else { ((((data[0] & 0xf) as usize) << 12) | ((data[1] as usize) << 4) | (data[2] >> 4) as usize, 20) };
        (0..len).map(|i| (0..8).fold(0u8, |a, b| (a << 1) | ((data[(start + i * 8 + b) / 8] >> (7 - (start + i * 8 + b) % 8)) & 1))).collect()
    }

    #[test]
    fn round_trips_every_version_and_renders() {
        for (v, n) in [(1, 14), (2, 26), (3, 42), (4, 62), (5, 84), (6, 106), (7, 122), (8, 152), (9, 180), (10, 213)] {
            let msg: Vec<u8> = (0..n).map(|i| b"eyJ1cmwiOiJ3czovL2"[i % 18]).collect();
            let q = Qr::encode(&msg).unwrap();
            assert_eq!((q.version, q.size), (v, 17 + 4 * v));
            assert_eq!(decode(&q), msg, "version {v}");
            if n < 213 {
                assert_eq!(Qr::encode(&vec![b'x'; n + 1]).unwrap().version, v + 1, "capacity boundary after v{v}");
            }
        }
        assert!(Qr::encode(&[0u8; 214]).is_none());
        let q = Qr::encode(b"hi").unwrap();
        // Finder corners: dark ring, light separator.
        assert!(q.dark(0, 0) && q.dark(6, 6) && !q.dark(7, 7) && q.dark(3, 3) && !q.dark(1, 1));
        let r = q.render(2);
        assert_eq!(r.lines().count(), 13);
        assert!(r.lines().all(|l| l.chars().count() == 25));
    }
}
