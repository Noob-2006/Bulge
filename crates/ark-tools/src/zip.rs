//! Just enough ZIP (OOXML / ODF / EPUB packages) and DEFLATE (also PDF FlateDecode
//! streams) to extract document text. Inflate is the canonical-Huffman scheme of
//! zlib's `contrib/puff`, like ark-channel's zlib stream decoder.

const LBASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
const MAX_BITS: usize = 15;

type Res<T> = Result<T, String>;

struct Huff {
    count: [u16; MAX_BITS + 1],
    symbol: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Res<Huff> {
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lengths {
            count[l as usize] += 1;
        }
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - c as i32;
            if left < 0 {
                return Err("over-subscribed Huffman code".into());
            }
        }
        let mut offs = [0u16; MAX_BITS + 1];
        for l in 1..MAX_BITS {
            offs[l + 1] = offs[l] + count[l];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (s, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huff { count, symbol })
    }
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    cnt: u32,
}

impl Bits<'_> {
    fn bits(&mut self, n: u32) -> Res<u32> {
        while self.cnt < n {
            let b = *self.data.get(self.pos).ok_or("truncated deflate data")?;
            self.pos += 1;
            self.buf |= (b as u32) << self.cnt;
            self.cnt += 8;
        }
        let v = self.buf & ((1u64 << n) - 1) as u32;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }
    fn decode(&mut self, h: &Huff) -> Res<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= self.bits(1)? as i32;
            let count = h.count[len] as i32;
            if code - count < first {
                return Ok(h.symbol[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("invalid Huffman code".into())
    }
}

fn dynamic(r: &mut Bits) -> Res<(Huff, Huff)> {
    let nlen = r.bits(5)? as usize + 257;
    let ndist = r.bits(5)? as usize + 1;
    let ncode = r.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err("bad dynamic block counts".into());
    }
    let mut cl = [0u8; 19];
    for &i in &CL_ORDER[..ncode] {
        cl[i] = r.bits(3)? as u8;
    }
    let ch = Huff::new(&cl)?;
    let mut lengths = vec![0u8; nlen + ndist];
    let mut i = 0;
    while i < nlen + ndist {
        let sym = r.decode(&ch)?;
        let (val, rep) = match sym {
            0..=15 => (sym as u8, 1),
            16 => (*lengths[..i].last().ok_or("repeat with no previous length")?, 3 + r.bits(2)? as usize),
            17 => (0, 3 + r.bits(3)? as usize),
            18 => (0, 11 + r.bits(7)? as usize),
            _ => return Err("bad code length symbol".into()),
        };
        if i + rep > nlen + ndist {
            return Err("too many code lengths".into());
        }
        lengths[i..i + rep].fill(val);
        i += rep;
    }
    if lengths[256] == 0 {
        return Err("no end-of-block code".into());
    }
    Ok((Huff::new(&lengths[..nlen])?, Huff::new(&lengths[nlen..])?))
}

/// Raw DEFLATE (RFC 1951), output capped at `cap` bytes (decompression bombs).
pub fn inflate(data: &[u8], cap: usize) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    let mut r = Bits { data, pos: 0, buf: 0, cnt: 0 };
    loop {
        let last = r.bits(1)? == 1;
        match r.bits(2)? {
            0 => {
                r.buf = 0;
                r.cnt = 0;
                let d = r.data.get(r.pos..r.pos + 4).ok_or("truncated stored block")?;
                let (len, nlen) = (u16::from_le_bytes([d[0], d[1]]), u16::from_le_bytes([d[2], d[3]]));
                if len != !nlen {
                    return Err("stored block length mismatch".into());
                }
                r.pos += 4;
                out.extend_from_slice(r.data.get(r.pos..r.pos + len as usize).ok_or("truncated stored block")?);
                r.pos += len as usize;
            }
            t @ (1 | 2) => {
                let (l, d) = if t == 1 {
                    let mut l = [8u8; 288];
                    l[144..256].fill(9);
                    l[256..280].fill(7);
                    (Huff::new(&l)?, Huff::new(&[5u8; 30])?)
                } else {
                    dynamic(&mut r)?
                };
                loop {
                    let sym = r.decode(&l)? as usize;
                    match sym {
                        0..=255 => out.push(sym as u8),
                        256 => break,
                        257..=285 => {
                            let i = sym - 257;
                            let len = LBASE[i] as usize + r.bits(LEXT[i] as u32)? as usize;
                            let ds = r.decode(&d)? as usize;
                            if ds >= 30 {
                                return Err("bad distance symbol".into());
                            }
                            let dist = DBASE[ds] as usize + r.bits(DEXT[ds] as u32)? as usize;
                            if dist > out.len() {
                                return Err("distance too far back".into());
                            }
                            let from = out.len() - dist;
                            for k in 0..len {
                                out.push(out[from + k]);
                            }
                        }
                        _ => return Err("bad literal/length symbol".into()),
                    }
                    if out.len() > cap {
                        return Err(format!("inflated data exceeds {cap} bytes"));
                    }
                }
            }
            _ => return Err("invalid deflate block type".into()),
        }
        if out.len() > cap {
            return Err(format!("inflated data exceeds {cap} bytes"));
        }
        if last {
            return Ok(out);
        }
    }
}

/// zlib (RFC 1950) wrapper; falls back to raw deflate when the header is absent.
pub fn zlib_decompress(data: &[u8], cap: usize) -> Res<Vec<u8>> {
    if data.len() >= 2 && data[0] & 0x0f == 8 && (((data[0] as u16) << 8) | data[1] as u16).is_multiple_of(31) {
        return inflate(&data[2..], cap);
    }
    inflate(data, cap)
}

pub struct Zip<'a> {
    data: &'a [u8],
    /// (name, method, compressed size, uncompressed size, local header offset)
    entries: Vec<(String, u16, usize, usize, usize)>,
}

fn u16le(d: &[u8], at: usize) -> Res<u16> {
    d.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| "truncated zip".into())
}
fn u32le(d: &[u8], at: usize) -> Res<u32> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or_else(|| "truncated zip".into())
}

impl<'a> Zip<'a> {
    pub fn open(data: &'a [u8]) -> Res<Zip<'a>> {
        // End of central directory: last PK\x05\x06 within the final 64 KiB + 22 bytes.
        let lo = data.len().saturating_sub(65_557);
        let eocd = (lo..data.len().saturating_sub(21)).rev().find(|&i| data[i..].starts_with(b"PK\x05\x06")).ok_or("File is not a zip file")?;
        let n = u16le(data, eocd + 10)? as usize;
        let mut at = u32le(data, eocd + 16)? as usize;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            if u32le(data, at)? != 0x0201_4b50 {
                return Err("bad central directory".into());
            }
            let method = u16le(data, at + 10)?;
            let csize = u32le(data, at + 20)? as usize;
            let usize_ = u32le(data, at + 24)? as usize;
            let (nl, el, cl) = (u16le(data, at + 28)? as usize, u16le(data, at + 30)? as usize, u16le(data, at + 32)? as usize);
            let off = u32le(data, at + 42)? as usize;
            let name = String::from_utf8_lossy(data.get(at + 46..at + 46 + nl).ok_or("truncated zip")?).into_owned();
            entries.push((name, method, csize, usize_, off));
            at += 46 + nl + el + cl;
        }
        Ok(Zip { data, entries })
    }

    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.0.as_str()).collect()
    }

    pub fn read(&self, name: &str) -> Res<Vec<u8>> {
        let (_, method, csize, usize_, off) = self.entries.iter().find(|e| e.0 == name).ok_or_else(|| format!("Missing {name}"))?;
        let d = self.data;
        if u32le(d, *off)? != 0x0403_4b50 {
            return Err(format!("bad local header for {name}"));
        }
        let start = off + 30 + u16le(d, off + 26)? as usize + u16le(d, off + 28)? as usize;
        let body = d.get(start..start + csize).ok_or("truncated zip entry")?;
        match method {
            0 => Ok(body.to_vec()),
            8 => inflate(body, (*usize_).max(1) * 2 + 1024),
            m => Err(format!("unsupported zip compression method {m} for {name}")),
        }
    }

    pub fn read_str(&self, name: &str) -> Res<String> {
        Ok(String::from_utf8_lossy(&self.read(name)?).into_owned())
    }
}

/// A stored-only zip writer for tests.
#[cfg(test)]
pub fn write_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, body) in files {
        let off = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0; 12]);
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

#[cfg(test)]
pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflate_python_vectors() {
        // zlib.compressobj(9, DEFLATED, -15) of a repetitive 545-byte text (dynamic Huffman).
        let raw = unhex("cb48cdc9c957c84022cbf38b725274508446258695444846aa4261696672b64252517e799e425a7e854256696e41b1427e596a914209503a27b1aa5221253f5d8f0b00");
        let out = inflate(&raw, 10_000).unwrap();
        assert_eq!(out.len(), 545);
        assert!(out.ends_with(b"lazy dog.\n"));
        assert!(inflate(&raw, 100).is_err(), "cap enforced");
        let z = unhex("789c730a51d0f048cdc9c957087071d35408c952700d01003ae0058d");
        assert_eq!(zlib_decompress(&z, 1000).unwrap(), b"BT (Hello PDF) Tj ET");
        assert!(inflate(&[0xff], 10).is_err());
    }

    #[test]
    fn zip_roundtrip_and_errors() {
        let z = write_stored(&[("a.txt", b"alpha"), ("dir/b.xml", b"<x/>")]);
        let zip = Zip::open(&z).unwrap();
        assert_eq!(zip.names(), vec!["a.txt", "dir/b.xml"]);
        assert_eq!(zip.read_str("dir/b.xml").unwrap(), "<x/>");
        assert!(zip.read("nope").unwrap_err().contains("Missing"));
        assert!(Zip::open(b"not a zip at all, definitely not").is_err());
    }
}
