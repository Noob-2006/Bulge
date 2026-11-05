//! Minimal ZIP reader for registry downloads (ClawHub `/download`): central directory,
//! stored and deflate members. Unsafe member paths are skipped, as are members over
//! `max_member` bytes, non-UTF-8 members and anything that is not a regular file (a Unix
//! symlink member is refused, never written) (Hermes `_download_zip`). The decompressed total is
//! capped at the download limit so a ZIP bomb cannot exhaust memory.

use std::collections::BTreeMap;

/// Decompressed-byte ceiling for one archive (Hermes `ZIP_DOWNLOAD_MAX_BYTES`, same as
/// `hub::http::MAX_BODY` for the compressed stream).
pub const MAX_TOTAL: usize = 25 * 1024 * 1024;

fn u16le(b: &[u8], o: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?) as usize)
}
fn u32le(b: &[u8], o: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?) as usize)
}

/// Every member as raw bytes (`None` for a corrupt, oversized or bomb-shaped archive).
pub fn members(data: &[u8], max_member: usize) -> Option<BTreeMap<String, Vec<u8>>> {
    members_within(data, max_member, MAX_TOTAL)
}

fn members_within(data: &[u8], max_member: usize, max_total: usize) -> Option<BTreeMap<String, Vec<u8>>> {
    let eocd = (0..data.len().saturating_sub(21)).rev().find(|&i| data[i..].starts_with(b"PK\x05\x06"))?;
    let count = u16le(data, eocd + 10)?;
    let mut off = u32le(data, eocd + 16)?;
    let mut out = BTreeMap::new();
    let mut total = 0usize;
    for _ in 0..count {
        if !data.get(off..)?.starts_with(b"PK\x01\x02") {
            return None;
        }
        let method = u16le(data, off + 10)?;
        let csize = u32le(data, off + 20)?;
        let usize_ = u32le(data, off + 24)?;
        let (nlen, elen, clen) = (u16le(data, off + 28)?, u16le(data, off + 30)?, u16le(data, off + 32)?);
        let attr = u32le(data, off + 38)? >> 16;
        let local = u32le(data, off + 42)?;
        let name = String::from_utf8_lossy(data.get(off + 46..off + 46 + nlen)?).to_string();
        off += 46 + nlen + elen + clen;
        if name.ends_with('/') || usize_ > max_member {
            continue;
        }
        // Unix mode lives in the high half of the external attributes. Only plain regular files (or
        // DOS-attributed entries, which leave it 0) are written: a symlink/device/FIFO member would
        // otherwise be materialised from its target path bytes.
        if attr != 0 && attr & 0o170000 != 0o100000 {
            continue;
        }
        let Ok(name) = super::model::validate_rel(&name) else { continue };
        if !data.get(local..)?.starts_with(b"PK\x03\x04") {
            return None;
        }
        let start = local + 30 + u16le(data, local + 26)? + u16le(data, local + 28)?;
        let raw = data.get(start..start + csize)?;
        let body = match method {
            0 => raw.to_vec(),
            8 => match miniz_oxide::inflate::decompress_to_vec_with_limit(raw, max_member) {
                Ok(b) => b,
                Err(_) => continue,
            },
            _ => continue,
        };
        total += body.len();
        if total > max_total {
            return None;
        }
        out.insert(name, body);
    }
    Some(out)
}

/// UTF-8 text members only (what a skill bundle carries from a registry ZIP).
pub fn text_members(data: &[u8], max_member: usize) -> BTreeMap<String, Vec<u8>> {
    members(data, max_member).unwrap_or_default().into_iter().filter(|(_, b)| std::str::from_utf8(b).is_ok()).collect()
}

/// Build a stored (uncompressed) ZIP — used by tests and `seagent skills publish --to clawhub`.
pub fn build_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
    let crc = |d: &[u8]| {
        let mut c: u32 = 0xffff_ffff;
        for &b in d {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
            }
        }
        !c
    };
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for (name, data) in files {
        let off = out.len() as u32;
        let c = crc(data);
        let mut h = Vec::new();
        h.extend(b"PK\x03\x04");
        h.extend(20u16.to_le_bytes());
        h.extend([0u8; 4]);
        h.extend([0u8; 4]);
        h.extend(c.to_le_bytes());
        h.extend((data.len() as u32).to_le_bytes());
        h.extend((data.len() as u32).to_le_bytes());
        h.extend((name.len() as u16).to_le_bytes());
        h.extend(0u16.to_le_bytes());
        out.extend(&h);
        out.extend(name.as_bytes());
        out.extend(*data);
        let mut cd = Vec::new();
        cd.extend(b"PK\x01\x02");
        cd.extend(20u16.to_le_bytes());
        cd.extend(20u16.to_le_bytes());
        cd.extend([0u8; 4]);
        cd.extend([0u8; 4]);
        cd.extend(c.to_le_bytes());
        cd.extend((data.len() as u32).to_le_bytes());
        cd.extend((data.len() as u32).to_le_bytes());
        cd.extend((name.len() as u16).to_le_bytes());
        cd.extend([0u8; 12]);
        cd.extend(off.to_le_bytes());
        cd.extend(name.as_bytes());
        central.extend(cd);
    }
    let cd_off = out.len() as u32;
    out.extend(&central);
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(cd_off.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set the Unix mode (high half of the external attributes) of a central-directory entry.
    fn set_mode(z: &mut [u8], member: &str, mode: u32) {
        let mut i = 0;
        while i + 46 <= z.len() {
            if z[i..].starts_with(b"PK\x01\x02") {
                let n = u16::from_le_bytes([z[i + 28], z[i + 29]]) as usize;
                if &z[i + 46..i + 46 + n] == member.as_bytes() {
                    z[i + 38..i + 42].copy_from_slice(&(mode << 16).to_le_bytes());
                    return;
                }
            }
            i += 1;
        }
        panic!("member {member} not found");
    }

    #[test]
    fn stored_and_deflate_round_trip_unsafe_skipped() {
        let z = build_stored(&[("SKILL.md", b"---\nname: x\n---\nhi"), ("../evil.sh", b"rm"), ("bin.dat", &[0xff, 0xfe]), ("refs/a.md", b"a")]);
        let t = text_members(&z, 1000);
        assert_eq!(t.keys().collect::<Vec<_>>(), ["SKILL.md", "refs/a.md"]);
        assert!(members(b"not a zip", 10).is_none());
        // Deflate member: patch a stored archive's method and payload.
        let comp = miniz_oxide::deflate::compress_to_vec(b"hello hello hello", 6);
        let mut z = build_stored(&[("a.txt", &vec![0u8; comp.len()])]);
        let p = z.windows(5).position(|w| w == b"a.txt").unwrap() + 5;
        z[p..p + comp.len()].copy_from_slice(&comp);
        z[8] = 8;
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[cd + 10] = 8;
        z[cd + 24..cd + 28].copy_from_slice(&17u32.to_le_bytes());
        assert_eq!(members(&z, 1000).unwrap()["a.txt"], b"hello hello hello");
    }

    #[test]
    fn refuses_symlink_and_odd_mode_members() {
        let mut z = build_stored(&[("SKILL.md", b"---\nname: x\n---\nhi"), ("passwd", b"/etc/passwd"), ("fifo", b""), ("ok.md", b"ok")]);
        set_mode(&mut z, "passwd", 0o120777); // S_IFLNK
        set_mode(&mut z, "fifo", 0o010644); // S_IFIFO
        set_mode(&mut z, "SKILL.md", 0o100644); // regular, mode set the way real zips do
        let m = members(&z, 1000).unwrap();
        assert_eq!(m.keys().collect::<Vec<_>>(), ["SKILL.md", "ok.md"], "symlink target bytes never materialise as a file");
    }

    #[test]
    fn rejects_every_unsafe_member_shape() {
        let z = build_stored(&[("/etc/passwd", b"a"), ("C:/win.ini", b"b"), ("..", b"c"), ("a/../../b", b"d"), ("..\\evil.bat", b"e"), ("deep/../../out", b"f"), ("good.md", b"ok")]);
        assert_eq!(text_members(&z, 1000).keys().collect::<Vec<_>>(), ["good.md"]);
    }

    #[test]
    fn caps_member_and_total_bytes() {
        let z = build_stored(&[("a.txt", b"0123456789"), ("b.txt", b"0123456789")]);
        assert!(members_within(&z, 1000, 15).is_none(), "decompressed total over the cap fails the whole archive");
        assert_eq!(members_within(&z, 1000, 20).unwrap().len(), 2);
        assert!(members(&z, 5).unwrap().is_empty(), "members over the per-file cap are skipped");
    }
}
