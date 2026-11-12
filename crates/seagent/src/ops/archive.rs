//! `.tar.gz` without dependencies: ustar (+ GNU long names, pax `path`) writer and
//! reader, gzip with a small LZ77 + fixed-Huffman deflate encoder, and inflate from
//! seagent-channel's decoder. Used by profile export/import, backups, snapshots, debug
//! bundles and self-update.

use std::path::{Component, Path, PathBuf};

pub const MAX_INFLATE: usize = 4 << 30;

// ───────────── crc32 / gzip ─────────────

pub fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    !data.iter().fold(!0u32, |c, b| t[((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8))
}

struct BitOut {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitOut {
    fn put(&mut self, v: u32, bits: u32) {
        self.acc |= (v as u64) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    /// Huffman codes are sent most-significant bit first.
    fn code(&mut self, code: u32, len: u32) {
        let mut r = 0;
        for i in 0..len {
            r |= ((code >> i) & 1) << (len - 1 - i);
        }
        self.put(r, len);
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

const LBASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

fn lit(w: &mut BitOut, sym: u32) {
    match sym {
        0..=143 => w.code(0x30 + sym, 8),
        144..=255 => w.code(0x190 + sym - 144, 9),
        256..=279 => w.code(sym - 256, 7),
        _ => w.code(0xc0 + sym - 280, 8),
    }
}

/// Raw deflate: greedy LZ77 (32 KiB window, hash chains) coded with the fixed Huffman tables.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    const WIN: usize = 32 * 1024;
    const HBITS: u32 = 15;
    let mut w = BitOut { out: Vec::with_capacity(data.len() / 2 + 16), acc: 0, n: 0 };
    w.put(1, 1); // final block
    w.put(1, 2); // fixed Huffman
    let mut head = vec![usize::MAX; 1 << HBITS];
    let mut prev = vec![usize::MAX; data.len().max(1)];
    let hash = |i: usize| -> usize { (((data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | data[i + 2] as u32).wrapping_mul(2_654_435_761) >> (32 - HBITS)) as usize };
    let mut i = 0;
    while i < data.len() {
        let (mut best_len, mut best_dist) = (0usize, 0usize);
        if i + 3 <= data.len() {
            let h = hash(i);
            let mut cand = head[h];
            let mut chain = 0;
            while cand != usize::MAX && i - cand <= WIN && chain < 48 {
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
                cand = prev[cand];
                chain += 1;
            }
            prev[i] = head[h];
            head[h] = i;
        }
        if best_len >= 3 {
            let li = LBASE.iter().rposition(|b| *b as usize <= best_len).unwrap();
            lit(&mut w, 257 + li as u32);
            w.put((best_len - LBASE[li] as usize) as u32, LEXT[li] as u32);
            let di = DBASE.iter().rposition(|b| *b as usize <= best_dist).unwrap();
            w.code(di as u32, 5);
            w.put((best_dist - DBASE[di] as usize) as u32, DEXT[di] as u32);
            for (j, p) in prev.iter_mut().enumerate().take(i + best_len).skip(i + 1) {
                if j + 3 <= data.len() {
                    let h = hash(j);
                    *p = head[h];
                    head[h] = j;
                }
            }
            i += best_len;
        } else {
            lit(&mut w, data[i] as u32);
            i += 1;
        }
    }
    lit(&mut w, 256);
    w.finish()
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut o = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    o.extend(deflate(data));
    o.extend(crc32(data).to_le_bytes());
    o.extend((data.len() as u32).to_le_bytes());
    o
}

/// Decode a gzip file (all members, RFC 1952), verifying CRC-32 and length.
pub fn gunzip(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
            return Err("not a gzip file".into());
        }
        let flg = data[3];
        let mut p = 10;
        if flg & 4 != 0 {
            let xlen = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
            p += 2 + xlen;
        }
        for bit in [8u8, 16] {
            if flg & bit != 0 {
                p += data.get(p..).and_then(|d| d.iter().position(|b| *b == 0)).ok_or("truncated gzip header")? + 1;
            }
        }
        if flg & 2 != 0 {
            p += 2;
        }
        let (body, used) = seagent_channel::discord::zlib::inflate_raw(data.get(p..).ok_or("truncated gzip")?, MAX_INFLATE)?;
        let t = data.get(p + used..p + used + 8).ok_or("truncated gzip trailer")?;
        if u32::from_le_bytes([t[0], t[1], t[2], t[3]]) != crc32(&body) {
            return Err("gzip CRC mismatch (corrupt archive)".into());
        }
        if u32::from_le_bytes([t[4], t[5], t[6], t[7]]) != body.len() as u32 {
            return Err("gzip length mismatch".into());
        }
        out.extend(body);
        data = &data[p + used + 8..];
        while data.first() == Some(&0) {
            data = &data[1..];
        }
    }
    Ok(out)
}

// ───────────── tar ─────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// Relative path, `/`-separated.
    pub path: String,
    pub data: Vec<u8>,
    pub mode: u32,
    pub dir: bool,
}

impl Entry {
    pub fn file(path: &str, data: Vec<u8>) -> Entry {
        Entry { path: path.into(), data, mode: 0o600, dir: false }
    }
}

fn octal(field: &mut [u8], v: u64) {
    let s = format!("{:0w$o}", v, w = field.len() - 1);
    field[..s.len()].copy_from_slice(s.as_bytes());
}

fn header(name: &[u8], size: u64, mode: u32, kind: u8, mtime: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    octal(&mut h[100..108], mode as u64);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], mtime);
    h[148..156].fill(b' ');
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| *b as u32).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

fn pad(o: &mut Vec<u8>) {
    while !o.len().is_multiple_of(512) {
        o.push(0);
    }
}

pub fn tar(entries: &[Entry]) -> Vec<u8> {
    let mtime = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut o = Vec::new();
    for e in entries {
        let mut name = e.path.trim_start_matches('/').to_string();
        if e.dir && !name.ends_with('/') {
            name.push('/');
        }
        if name.len() > 100 {
            // GNU long name record.
            let mut n = name.clone().into_bytes();
            n.push(0);
            o.extend(header(b"././@LongLink", n.len() as u64, 0o644, b'L', mtime));
            o.extend(&n);
            pad(&mut o);
        }
        o.extend(header(name.as_bytes(), if e.dir { 0 } else { e.data.len() as u64 }, e.mode, if e.dir { b'5' } else { b'0' }, mtime));
        if !e.dir {
            o.extend(&e.data);
            pad(&mut o);
        }
    }
    o.extend([0u8; 1024]);
    o
}

fn parse_octal(f: &[u8]) -> u64 {
    let s: String = f.iter().take_while(|b| **b != 0 && **b != b' ').map(|b| *b as char).collect();
    u64::from_str_radix(s.trim(), 8).unwrap_or(0)
}

fn cstr(f: &[u8]) -> String {
    String::from_utf8_lossy(&f[..f.iter().position(|b| *b == 0).unwrap_or(f.len())]).into_owned()
}

/// Regular files and directories; links and devices are skipped.
pub fn untar(data: &[u8]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let mut p = 0;
    let mut long: Option<String> = None;
    while p + 512 <= data.len() {
        let h = &data[p..p + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let stored: u32 = parse_octal(&h[148..156]) as u32;
        let sum: u32 = h.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { b' ' as u32 } else { *b as u32 }).sum();
        if stored != sum {
            return Err(format!("tar header checksum mismatch at offset {p}"));
        }
        let size = parse_octal(&h[124..136]) as usize;
        let kind = h[156];
        let body = data.get(p + 512..p + 512 + size).ok_or("truncated tar entry")?;
        let mut name = cstr(&h[..100]);
        if &h[257..262] == b"ustar" {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        match kind {
            b'L' => long = Some(cstr(body)),
            b'x' => {
                // pax: "len path=value\n" records
                for rec in String::from_utf8_lossy(body).lines() {
                    if let Some(v) = rec.split_once(' ').and_then(|(_, kv)| kv.strip_prefix("path=")) {
                        long = Some(v.to_string());
                    }
                }
            }
            b'0' | 0 | b'5' => {
                let path = long.take().unwrap_or(name);
                out.push(Entry { path: path.trim_end_matches('/').to_string(), data: if kind == b'5' { vec![] } else { body.to_vec() }, mode: parse_octal(&h[100..108]) as u32, dir: kind == b'5' });
            }
            _ => {
                long = None;
            }
        }
        p += 512 + size.div_ceil(512) * 512;
    }
    Ok(out)
}

/// `rel` joined under `root`, refusing absolute paths and `..` (archive path traversal).
pub fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let r = Path::new(rel);
    if r.is_absolute() || r.components().any(|c| matches!(c, Component::ParentDir | Component::Prefix(_) | Component::RootDir)) {
        return Err(format!("unsafe path in archive: {rel}"));
    }
    Ok(root.join(r))
}

/// Every file under `dir` as entries prefixed by `prefix`, skipping names `skip` rejects.
pub fn collect(dir: &Path, prefix: &str, skip: &dyn Fn(&Path) -> bool, out: &mut Vec<Entry>) -> Result<(), String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Ok(()) };
    let mut items: Vec<_> = rd.flatten().collect();
    items.sort_by_key(|e| e.file_name());
    for e in items {
        let p = e.path();
        if skip(&p) {
            continue;
        }
        let name = format!("{prefix}{}", e.file_name().to_string_lossy());
        let ft = e.file_type().map_err(|x| x.to_string())?;
        if ft.is_dir() {
            out.push(Entry { path: name.clone(), data: vec![], mode: 0o700, dir: true });
            collect(&p, &format!("{name}/"), skip, out)?;
        } else if ft.is_file() {
            let mode = crate::ops::hostos::mode_of(&p).map(|m| m & 0o777).unwrap_or(0o600);
            out.push(Entry { path: name, data: std::fs::read(&p).map_err(|x| format!("{}: {x}", p.display()))?, mode, dir: false });
        }
    }
    Ok(())
}

/// Write entries under `root` (paths checked), keeping file modes.
pub fn extract(entries: &[Entry], root: &Path) -> Result<usize, String> {
    let mut n = 0;
    for e in entries {
        let p = safe_join(root, &e.path)?;
        if e.dir {
            std::fs::create_dir_all(&p).map_err(|x| format!("{}: {x}", p.display()))?;
            continue;
        }
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|x| format!("{}: {x}", d.display()))?;
        }
        std::fs::write(&p, &e.data).map_err(|x| format!("{}: {x}", p.display()))?;
        let _ = crate::ops::hostos::set_mode(&p, if e.mode == 0 { 0o600 } else { e.mode & 0o777 });
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflate_roundtrips_and_compresses() {
        let text: Vec<u8> = (0..2000).flat_map(|i| format!("{{\"seq\":{i},\"type\":\"message\",\"text\":\"hello world\"}}\n").into_bytes()).collect();
        for sample in [&b""[..], b"a", b"abcabcabcabcabc", &text, &(0..=255u8).cycle().take(70_000).collect::<Vec<u8>>()] {
            let gz = gzip(sample);
            assert_eq!(gunzip(&gz).unwrap(), sample);
        }
        assert!(gzip(&text).len() * 4 < text.len(), "compresses JSONL well: {} vs {}", gzip(&text).len(), text.len());
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let mut bad = gzip(b"hello");
        let n = bad.len();
        bad[n - 6] ^= 1;
        assert!(gunzip(&bad).unwrap_err().contains("CRC"));
        // Output of the system gzip (dynamic Huffman) decodes too.
        if let Ok(o) = seagent_core::platform::layout::program_command("sh").arg("-c").arg("printf 'system gzip stream system gzip stream' | gzip -9").output() {
            if o.status.success() && !o.stdout.is_empty() {
                assert_eq!(gunzip(&o.stdout).unwrap(), b"system gzip stream system gzip stream");
            }
        }
    }

    #[test]
    fn tar_roundtrip_long_names_and_traversal() {
        let long = format!("{}/file.txt", "d".repeat(120));
        let entries = vec![Entry { path: "dir".into(), data: vec![], mode: 0o700, dir: true }, Entry::file("dir/a.txt", b"A".to_vec()), Entry::file(&long, b"L".repeat(700))];
        let back = untar(&gunzip(&gzip(&tar(&entries))).unwrap()).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back[2].path, long);
        assert_eq!(back[2].data.len(), 700);
        assert!(safe_join(Path::new("/r"), "../etc/passwd").is_err());
        assert!(safe_join(Path::new("/r"), "/etc/passwd").is_err());
        let root = seagent_core::tmp::scratch_path(format!("seagent-tar-{}", seagent_kernel::util::random_hex(4)));
        assert_eq!(extract(&back, &root).unwrap(), 2);
        assert_eq!(std::fs::read(root.join("dir/a.txt")).unwrap(), b"A");
        // The system tar reads ours.
        let f = root.join("t.tar.gz");
        std::fs::write(&f, gzip(&tar(&entries[..2]))).unwrap();
        if let Ok(o) = seagent_core::platform::proc::command("tar").arg("-tzf").arg(&f).output() {
            if o.status.success() {
                assert!(String::from_utf8_lossy(&o.stdout).contains("dir/a.txt"));
            }
        }
    }
}
