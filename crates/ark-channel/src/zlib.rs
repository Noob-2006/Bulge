//! Inflate (RFC 1950 zlib / RFC 1951 deflate) for Discord's `compress=zlib-stream`
//! gateway transport: one zlib context for the whole connection, every message
//! ends with a Z_SYNC_FLUSH (empty stored block, `00 00 FF FF`), so each
//! completed message holds whole deflate blocks and only the 32 KiB sliding
//! window carries over. Decoding is the canonical-Huffman scheme of zlib's
//! `contrib/puff` (count/symbol tables, one bit at a time).

const WINDOW: usize = 32 * 1024;
const SUFFIX: [u8; 4] = [0, 0, 0xff, 0xff];
const MAX_BITS: usize = 15;

const LBASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

type Res<T> = Result<T, String>;

struct Huff {
    count: [u16; MAX_BITS + 1],
    symbol: Vec<u16>,
}

impl Huff {
    /// Canonical code from code lengths; over-subscribed sets are rejected, incomplete ones allowed.
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

    /// Drop the rest of the current byte.
    fn align(&mut self) {
        self.buf = 0;
        self.cnt = 0;
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

/// A zlib stream decoded message by message.
pub struct ZlibStream {
    pending: Vec<u8>,
    window: Vec<u8>,
    header: bool,
    done: bool,
    /// Cap on one message (compressed and inflated), against decompression bombs.
    pub limit: usize,
}

impl Default for ZlibStream {
    fn default() -> Self {
        ZlibStream { pending: Vec::new(), window: Vec::new(), header: false, done: false, limit: 64 * 1024 * 1024 }
    }
}

impl ZlibStream {
    /// Feed one WebSocket frame; `Some(bytes)` once a message is complete (ends with the flush suffix).
    pub fn push(&mut self, frame: &[u8]) -> Res<Option<Vec<u8>>> {
        self.pending.extend_from_slice(frame);
        if self.pending.len() > self.limit {
            return Err("compressed gateway message too large".into());
        }
        if !self.pending.ends_with(&SUFFIX) {
            return Ok(None);
        }
        let input = std::mem::take(&mut self.pending);
        self.inflate(&input).map(Some)
    }

    fn inflate(&mut self, input: &[u8]) -> Res<Vec<u8>> {
        if self.done {
            return Err("data after the end of the zlib stream".into());
        }
        let mut start = 0;
        if !self.header {
            let (cmf, flg) = (*input.first().ok_or("empty zlib stream")?, *input.get(1).ok_or("short zlib header")?);
            if cmf & 0x0f != 8 || cmf >> 4 > 7 || !(((cmf as u16) << 8) | flg as u16).is_multiple_of(31) {
                return Err("bad zlib header".into());
            }
            if flg & 0x20 != 0 {
                return Err("zlib preset dictionary not supported".into());
            }
            self.header = true;
            start = 2;
        }
        let hist = self.window.len();
        let mut out = std::mem::take(&mut self.window);
        let mut r = Bits { data: &input[start..], pos: 0, buf: 0, cnt: 0 };
        while r.pos < r.data.len() {
            let last = r.bits(1)? == 1;
            match r.bits(2)? {
                0 => {
                    r.align();
                    let d = r.data.get(r.pos..r.pos + 4).ok_or("truncated stored block")?;
                    let (len, nlen) = (u16::from_le_bytes([d[0], d[1]]), u16::from_le_bytes([d[2], d[3]]));
                    if len != !nlen {
                        return Err("stored block length mismatch".into());
                    }
                    r.pos += 4;
                    let body = r.data.get(r.pos..r.pos + len as usize).ok_or("truncated stored block")?;
                    out.extend_from_slice(body);
                    r.pos += len as usize;
                }
                1 => {
                    let (l, d) = fixed();
                    codes(&mut r, &mut out, &l, &d, hist + self.limit)?;
                }
                2 => {
                    let (l, d) = dynamic(&mut r)?;
                    codes(&mut r, &mut out, &l, &d, hist + self.limit)?;
                }
                _ => return Err("invalid deflate block type".into()),
            }
            if last {
                // Adler-32 trailer follows; nothing more may come on this connection.
                r.align();
                self.done = true;
                break;
            }
        }
        let msg = out[hist..].to_vec();
        let keep = out.len().saturating_sub(WINDOW);
        out.drain(..keep);
        self.window = out;
        Ok(msg)
    }
}

fn fixed() -> (Huff, Huff) {
    let mut l = [8u8; 288];
    l[144..256].fill(9);
    l[256..280].fill(7);
    (Huff::new(&l).unwrap(), Huff::new(&[5u8; 30]).unwrap())
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

fn codes(r: &mut Bits, out: &mut Vec<u8>, l: &Huff, d: &Huff, cap: usize) -> Res<()> {
    loop {
        let sym = r.decode(l)? as usize;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            257..=285 => {
                let i = sym - 257;
                let len = LBASE[i] as usize + r.bits(LEXT[i] as u32)? as usize;
                let ds = r.decode(d)? as usize;
                if ds >= 30 {
                    return Err("bad distance symbol".into());
                }
                let dist = DBASE[ds] as usize + r.bits(DEXT[ds] as u32)? as usize;
                if dist > out.len() || dist > WINDOW {
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
            return Err("inflated gateway message too large".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("testdata/zlib/discord-stream.json")).unwrap()
    }

    fn frames(v: &Value) -> Vec<Vec<u8>> {
        v["frames"].as_array().unwrap().iter().map(|f| ark_net::crypto::b64_decode(f.as_str().unwrap()).unwrap()).collect()
    }

    /// Streams produced by python3 zlib (tools/gen_discord_zlib_vectors.py): dynamic, stored
    /// and fixed Huffman blocks, messages split across frames, 45 KB messages back-referencing
    /// the previous message through the 32 KiB window.
    #[test]
    fn python_zlib_sync_flush_streams() {
        let v = vectors();
        for name in ["default", "stored", "fixed", "gateway"] {
            let mut z = ZlibStream::default();
            let mut got = Vec::new();
            for f in frames(&v[name]) {
                if let Some(m) = z.push(&f).unwrap() {
                    got.push(String::from_utf8(m).unwrap());
                }
            }
            let want: Vec<String> = v[name]["messages"].as_array().unwrap().iter().map(|m| m.as_str().unwrap().to_string()).collect();
            assert_eq!(got, want, "{name}");
            assert!(z.window.len() <= WINDOW);
        }
    }

    #[test]
    fn corrupt_and_oversized_input_is_rejected() {
        let v = vectors();
        let f = frames(&v["default"]);
        let mut bad = f[0].clone();
        bad[0] = 0x79;
        assert!(ZlibStream::default().push(&bad).is_err(), "bad header");
        // A later frame without the earlier window: distances reach before the start.
        let mut z = ZlibStream { header: true, ..Default::default() };
        assert!(f[1..].iter().any(|x| z.push(x).is_err()));
        let mut z = ZlibStream { limit: 1000, ..Default::default() };
        assert!(f.iter().any(|x| z.push(x).is_err()), "45 KB message over a 1000-byte cap");
        // Over-subscribed code lengths.
        assert!(Huff::new(&[1, 1, 1]).is_err());
    }
}
