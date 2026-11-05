//! Minimal PNG codec for pet spritesheets (no image crate in the tree): decode 8/16-bit
//! grey, grey+alpha, RGB, RGBA and palette (+tRNS) non-interlaced images to RGBA, and
//! encode RGBA with a small LZ77 + fixed-Huffman deflate. Plus the few pixel operations
//! the pet renderer and hatcher need (crop, nearest resize, mirror, blit).

use seagent_channel::discord::zlib::inflate_raw;

#[derive(Debug, Clone, PartialEq)]
pub struct Rgba {
    pub w: usize,
    pub h: usize,
    /// Row-major RGBA8.
    pub px: Vec<u8>,
}

const SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
const MAX_PIXELS: usize = 64 * 1024 * 1024;

pub fn is_png(b: &[u8]) -> bool {
    b.starts_with(SIG)
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

pub fn decode(bytes: &[u8]) -> Result<Rgba, String> {
    if !is_png(bytes) {
        return Err("not a PNG file".into());
    }
    let mut i = 8;
    let (mut w, mut h, mut depth, mut ctype) = (0usize, 0usize, 0u8, 0u8);
    let mut idat = Vec::new();
    let mut plte: Vec<[u8; 3]> = vec![];
    let mut trns: Vec<u8> = vec![];
    while i + 8 <= bytes.len() {
        let len = be32(&bytes[i..]) as usize;
        let kind = &bytes[i + 4..i + 8];
        let data = bytes.get(i + 8..i + 8 + len).ok_or("truncated PNG chunk")?;
        match kind {
            b"IHDR" => {
                if len < 13 {
                    return Err("bad IHDR".into());
                }
                w = be32(data) as usize;
                h = be32(&data[4..]) as usize;
                depth = data[8];
                ctype = data[9];
                if data[12] != 0 {
                    return Err("interlaced PNGs are not supported".into());
                }
            }
            b"PLTE" => plte = data.chunks(3).filter(|c| c.len() == 3).map(|c| [c[0], c[1], c[2]]).collect(),
            b"tRNS" => trns = data.to_vec(),
            b"IDAT" => idat.extend_from_slice(data),
            b"IEND" => break,
            _ => {}
        }
        i += 12 + len;
    }
    if w == 0 || h == 0 || w.saturating_mul(h) > MAX_PIXELS {
        return Err("PNG has no or too many pixels".into());
    }
    let channels = match ctype {
        0 => 1,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        _ => return Err(format!("unsupported PNG colour type {ctype}")),
    };
    if !(depth == 8 || depth == 16 || (ctype == 3 && depth <= 8) || (ctype == 0 && depth < 8)) {
        return Err(format!("unsupported PNG bit depth {depth}"));
    }
    let bits_pp = channels * depth as usize;
    let stride = (w * bits_pp).div_ceil(8);
    let bpp = bits_pp.div_ceil(8).max(1);
    if idat.len() < 2 {
        return Err("PNG has no image data".into());
    }
    let (raw, _) = inflate_raw(&idat[2..], h * (stride + 1) + 16)?;
    if raw.len() < h * (stride + 1) {
        return Err("PNG image data is truncated".into());
    }
    let mut cur = vec![0u8; stride];
    let mut prev = vec![0u8; stride];
    let mut px = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        let row = &raw[y * (stride + 1)..(y + 1) * (stride + 1)];
        let f = row[0];
        for x in 0..stride {
            let a = (if x >= bpp { cur[x - bpp] } else { 0 }) as i32;
            let b = prev[x] as i32;
            let c = (if x >= bpp { prev[x - bpp] } else { 0 }) as i32;
            let v = row[1 + x] as i32;
            cur[x] = (match f {
                0 => v,
                1 => v + a,
                2 => v + b,
                3 => v + (a + b) / 2,
                4 => {
                    let p = a + b - c;
                    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
                    v + if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c }
                }
                _ => return Err(format!("bad PNG filter {f}")),
            }) as u8;
        }
        for x in 0..w {
            let sample = |ch: usize| -> u8 {
                if depth == 16 {
                    cur[(x * channels + ch) * 2]
                } else if depth == 8 {
                    cur[x * channels + ch]
                } else {
                    let bit = x * depth as usize;
                    let v = (cur[bit / 8] >> (8 - depth as usize - bit % 8)) & ((1u16 << depth) - 1) as u8;
                    if ctype == 3 {
                        v
                    } else {
                        (v as u32 * 255 / ((1u32 << depth) - 1)) as u8
                    }
                }
            };
            let rgba = match ctype {
                0 => {
                    let g = sample(0);
                    let transparent = trns.len() >= 2 && depth == 8 && trns[1] == g;
                    [g, g, g, if transparent { 0 } else { 255 }]
                }
                2 => {
                    let (r, g, b) = (sample(0), sample(1), sample(2));
                    let transparent = trns.len() >= 6 && depth == 8 && trns[1] == r && trns[3] == g && trns[5] == b;
                    [r, g, b, if transparent { 0 } else { 255 }]
                }
                3 => {
                    let idx = sample(0) as usize;
                    let c = plte.get(idx).copied().unwrap_or([0, 0, 0]);
                    [c[0], c[1], c[2], trns.get(idx).copied().unwrap_or(255)]
                }
                4 => {
                    let g = sample(0);
                    [g, g, g, sample(1)]
                }
                _ => [sample(0), sample(1), sample(2), sample(3)],
            };
            px.extend_from_slice(&rgba);
        }
        std::mem::swap(&mut cur, &mut prev);
    }
    Ok(Rgba { w, h, px })
}

/// Any sheet format: PNG through [`decode`], WebP / JPEG through the `image` crate.
pub fn decode_any(bytes: &[u8]) -> Result<Rgba, String> {
    if is_png(bytes) {
        return decode(bytes);
    }
    let img = image::load_from_memory(bytes).map_err(|e| format!("cannot decode image: {e}"))?.to_rgba8();
    let (w, h) = (img.width() as usize, img.height() as usize);
    if w == 0 || h == 0 || w.saturating_mul(h) > MAX_PIXELS {
        return Err("image has no or too many pixels".into());
    }
    Ok(Rgba { w, h, px: img.into_raw() })
}

// ───────────── deflate (LZ77 + fixed Huffman) ─────────────

struct BitW {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitW {
    fn put(&mut self, v: u32, bits: u32) {
        self.acc |= (v as u64) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    fn huff(&mut self, code: u32, len: u32) {
        let mut r = 0;
        for i in 0..len {
            r |= ((code >> i) & 1) << (len - 1 - i);
        }
        self.put(r, len);
    }
    fn lit(&mut self, sym: u32) {
        match sym {
            0..=143 => self.huff(0x30 + sym, 8),
            144..=255 => self.huff(0x190 + sym - 144, 9),
            256..=279 => self.huff(sym - 256, 7),
            _ => self.huff(0xc0 + sym - 280, 8),
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

const LEN_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// Raw DEFLATE, one fixed-Huffman block, greedy LZ77 with short hash chains.
pub fn deflate_raw(data: &[u8]) -> Vec<u8> {
    const WIN: usize = 32768;
    const HSIZE: usize = 1 << 15;
    let mut w = BitW { out: Vec::with_capacity(data.len() / 4 + 16), acc: 0, n: 0 };
    w.put(1, 1); // final
    w.put(1, 2); // fixed Huffman
    let mut head = vec![usize::MAX; HSIZE];
    let mut prev = vec![usize::MAX; WIN];
    let hash = |i: usize| ((data[i] as usize) << 10 ^ (data[i + 1] as usize) << 5 ^ data[i + 2] as usize) & (HSIZE - 1);
    let mut i = 0;
    let insert = |i: usize, head: &mut Vec<usize>, prev: &mut Vec<usize>| {
        if i + 2 < data.len() {
            let h = hash(i);
            prev[i % WIN] = head[h];
            head[h] = i;
        }
    };
    while i < data.len() {
        let (mut best_len, mut best_dist) = (0usize, 0usize);
        if i + 2 < data.len() {
            let mut cand = head[hash(i)];
            let mut depth = 0;
            while cand != usize::MAX && i - cand <= WIN && depth < 24 {
                let max = (data.len() - i).min(258);
                let mut l = 0;
                while l < max && data[cand + l] == data[i + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_dist = i - cand;
                    if l == max {
                        break;
                    }
                }
                let nx = prev[cand % WIN];
                if nx == usize::MAX || nx >= cand {
                    break;
                }
                cand = nx;
                depth += 1;
            }
        }
        if best_len >= 3 {
            let li = LEN_BASE.iter().rposition(|b| *b as usize <= best_len).unwrap_or(0);
            w.lit(257 + li as u32);
            w.put((best_len - LEN_BASE[li] as usize) as u32, LEN_EXTRA[li] as u32);
            let di = DIST_BASE.iter().rposition(|b| *b as usize <= best_dist).unwrap_or(0);
            w.huff(di as u32, 5);
            w.put((best_dist - DIST_BASE[di] as usize) as u32, DIST_EXTRA[di] as u32);
            for k in i..i + best_len {
                insert(k, &mut head, &mut prev);
            }
            i += best_len;
        } else {
            w.lit(data[i] as u32);
            insert(i, &mut head, &mut prev);
            i += 1;
        }
    }
    w.lit(256);
    w.finish()
}

fn chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

pub fn encode(img: &Rgba) -> Vec<u8> {
    let mut raw = Vec::with_capacity(img.h * (img.w * 4 + 1));
    for y in 0..img.h {
        raw.push(0);
        raw.extend_from_slice(&img.px[y * img.w * 4..(y + 1) * img.w * 4]);
    }
    let mut z = vec![0x78, 0x01];
    z.extend(deflate_raw(&raw));
    z.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut out = SIG.to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(img.w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(img.h as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

// ───────────── pixel ops ─────────────

impl Rgba {
    pub fn new(w: usize, h: usize) -> Rgba {
        Rgba { w, h, px: vec![0; w * h * 4] }
    }
    pub fn get(&self, x: usize, y: usize) -> [u8; 4] {
        let i = (y * self.w + x) * 4;
        [self.px[i], self.px[i + 1], self.px[i + 2], self.px[i + 3]]
    }
    pub fn put(&mut self, x: usize, y: usize, c: [u8; 4]) {
        let i = (y * self.w + x) * 4;
        self.px[i..i + 4].copy_from_slice(&c);
    }
    /// Crop clamped to the image.
    pub fn crop(&self, x0: usize, y0: usize, w: usize, h: usize) -> Rgba {
        let (w, h) = (w.min(self.w.saturating_sub(x0)), h.min(self.h.saturating_sub(y0)));
        let mut o = Rgba::new(w, h);
        for y in 0..h {
            let s = ((y0 + y) * self.w + x0) * 4;
            o.px[y * w * 4..(y + 1) * w * 4].copy_from_slice(&self.px[s..s + w * 4]);
        }
        o
    }
    /// Nearest-neighbour resize (keeps pixel-art edges hard).
    pub fn resize(&self, w: usize, h: usize) -> Rgba {
        let mut o = Rgba::new(w.max(1), h.max(1));
        for y in 0..o.h {
            for x in 0..o.w {
                o.put(x, y, self.get((x * self.w / o.w).min(self.w - 1), (y * self.h / o.h).min(self.h - 1)));
            }
        }
        o
    }
    pub fn mirror(&self) -> Rgba {
        let mut o = Rgba::new(self.w, self.h);
        for y in 0..self.h {
            for x in 0..self.w {
                o.put(self.w - 1 - x, y, self.get(x, y));
            }
        }
        o
    }
    /// Alpha-composite `src` at (x, y).
    pub fn blit(&mut self, src: &Rgba, x0: usize, y0: usize) {
        for y in 0..src.h {
            for x in 0..src.w {
                let (dx, dy) = (x0 + x, y0 + y);
                if dx >= self.w || dy >= self.h {
                    continue;
                }
                let s = src.get(x, y);
                if s[3] == 0 {
                    continue;
                }
                if s[3] == 255 {
                    self.put(dx, dy, s);
                    continue;
                }
                let d = self.get(dx, dy);
                let a = s[3] as u32;
                let mix = |s: u8, d: u8| ((s as u32 * a + d as u32 * (255 - a)) / 255) as u8;
                self.put(dx, dy, [mix(s[0], d[0]), mix(s[1], d[1]), mix(s[2], d[2]), (a + d[3] as u32 * (255 - a) / 255) as u8]);
            }
        }
    }
    /// Bounding box of pixels with alpha above `floor`: (x0, y0, x1, y1) exclusive.
    pub fn bbox(&self, floor: u8) -> Option<(usize, usize, usize, usize)> {
        let (mut x0, mut y0, mut x1, mut y1) = (usize::MAX, usize::MAX, 0, 0);
        for y in 0..self.h {
            for x in 0..self.w {
                if self.get(x, y)[3] > floor {
                    x0 = x0.min(x);
                    y0 = y0.min(y);
                    x1 = x1.max(x + 1);
                    y1 = y1.max(y + 1);
                }
            }
        }
        (x0 != usize::MAX).then_some((x0, y0, x1, y1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_roundtrip_ops_and_known_file() {
        let mut img = Rgba::new(37, 23);
        for y in 0..23 {
            for x in 0..37 {
                img.put(x, y, if (x / 5 + y / 3) % 2 == 0 { [x as u8 * 7, y as u8 * 11, 200, 255] } else { [0, 0, 0, 0] });
            }
        }
        let bytes = encode(&img);
        assert!(is_png(&bytes));
        assert!(bytes.len() < 37 * 23 * 4, "compressed");
        assert_eq!(decode(&bytes).unwrap(), img);
        // A large mostly-transparent atlas stays small.
        let big = Rgba::new(1536, 1872);
        let enc = encode(&big);
        assert!(enc.len() < 200_000, "{}", enc.len());
        assert_eq!(decode(&enc).unwrap().w, 1536);
        // An externally produced 1x1 RGBA PNG (zlib default compression, filter 0).
        let one = base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==");
        let d = decode(&one).unwrap();
        assert_eq!((d.w, d.h), (1, 1));
        assert_eq!(d.get(0, 0)[3], 0xff);
        assert!(decode(b"GIF89a").is_err());
        assert!(decode_any(b"not an image").is_err());
        // A lossless WebP (encoded by the image crate) decodes to the same pixels.
        let mut webp = Vec::new();
        image::codecs::webp::WebPEncoder::new_lossless(&mut webp).encode(&img.px, 37, 23, image::ExtendedColorType::Rgba8).unwrap();
        assert_eq!(decode_any(&webp).unwrap(), img);
        let c = img.crop(30, 20, 20, 20);
        assert_eq!((c.w, c.h), (7, 3));
        assert_eq!(img.mirror().get(36, 0), img.get(0, 0));
        assert_eq!(img.resize(74, 46).get(2, 0), img.get(1, 0));
        let mut canvas = Rgba::new(10, 10);
        canvas.blit(&Rgba { w: 1, h: 1, px: vec![255, 0, 0, 255] }, 4, 5);
        assert_eq!(canvas.bbox(16), Some((4, 5, 5, 6)));
    }

    fn base64_decode(s: &str) -> Vec<u8> {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = vec![];
        let (mut acc, mut n) = (0u32, 0);
        for c in s.bytes().filter(|c| *c != b'=') {
            acc = acc << 6 | T.iter().position(|t| *t == c).unwrap() as u32;
            n += 6;
            if n >= 8 {
                n -= 8;
                out.push((acc >> n) as u8);
            }
        }
        out
    }
}
