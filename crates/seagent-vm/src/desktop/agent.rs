//! The guest agent inside the desktop VM: the same `seagent-vm-guest` binary the microVM boots
//! as PID 1, run by systemd in its `service` role (`seagent-agent.service` in the image), so
//! the agent's `shell` tool runs commands in the machine the person watches.
//!
//! Where the host gets that binary (it is never built on the user's machine):
//! 1. the microVM guest image this seagent uses (`crate::image::GuestImage::find`: the
//!    user-built `<data>/vm/image`, else the installer's bundle), whose initramfs carries the
//!    agent as `/sbin/init` and whose manifest records its sha256 ([`from_image`]);
//! 2. a `seagent-vm-guest` file next to the running executable or in `<data>/vm/` (development
//!    builds: `cargo build --target x86_64-unknown-linux-musl -p seagent-vm`).
//!
//! Only a static x86_64 Linux binary that has the `service` role is accepted
//! ([`crate::proto::GUEST_ROLES`] in its bytes): the desktop image is x86_64 Debian, and an older
//! agent would exit on the unknown role. The binary reaches the guest twice: baked into the
//! image at build time (served by the NoCloud seed server, `image::build`), and again at every
//! boot through fw_cfg (`opt/seagent/agent`, [`FW_CFG_AGENT_NAME`]), which the image's start
//! script prefers — so the in-VM agent always matches the host's protocol without rebuilding
//! the image after an upgrade.

use crate::image::GuestImage;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The desktop's login user (`users:` in `user-data.yaml`; LightDM logs it in automatically).
pub const GUEST_USER: &str = "seagent";
pub const GUEST_HOME: &str = "/home/seagent";
/// Where the host workspaces are mirrored inside the VM (one sub-directory each) and where a
/// command without a mapped cwd starts.
pub const GUEST_WORKSPACE: &str = "/home/seagent/workspace";
/// virtio-serial port name of the agent channel (`/dev/virtio-ports/seagent0` in the guest).
pub const GUEST_PORT: &str = "seagent0";
/// fw_cfg item carrying the host's agent binary at every boot.
pub const FW_CFG_AGENT_NAME: &str = "opt/seagent/agent";
/// Path of the agent on the build-time seed server.
pub const SEED_AGENT_FILE: &str = "seagent-vm-guest";
/// A guest agent is a few MiB; anything far larger is not one.
const MAX_AGENT_BYTES: u64 = 64 << 20;
/// Bound on the decompressed initramfs read while looking for the agent.
const MAX_INITRAMFS_BYTES: u64 = 1 << 30;

/// One agent binary and where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentBinary {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub source: String,
}

impl AgentBinary {
    fn new(bytes: Vec<u8>, source: String) -> AgentBinary {
        let sha256 = seagent_net::crypto::hex(&seagent_net::crypto::sha256(&bytes));
        AgentBinary { bytes, sha256, source }
    }
}

/// Does this binary have the `service` role (the marker string is in its bytes)?
pub fn has_service_role(bin: &[u8]) -> bool {
    let m = crate::proto::GUEST_ROLES.as_bytes();
    bin.windows(m.len()).any(|w| w == m)
}

/// A 64-bit little-endian x86_64 ELF (what the x86_64 desktop image can execute).
pub fn is_x86_64_linux_elf(b: &[u8]) -> bool {
    b.len() > 20 && &b[..4] == b"\x7fELF" && b[4] == 2 && b[5] == 1 && u16::from_le_bytes([b[18], b[19]]) == 0x3e
}

fn hex_field(h: &[u8], i: usize) -> Result<u64, String> {
    let s = std::str::from_utf8(&h[6 + i * 8..6 + (i + 1) * 8]).map_err(|_| "cpio: header is not ASCII".to_string())?;
    u64::from_str_radix(s, 16).map_err(|_| format!("cpio: bad header field {s:?}"))
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// The contents of the first of `names` in a newc (`070701` / `070702`) cpio archive. Names are
/// compared without a leading `./` or `/`. A hard link is followed to the entry that carries
/// its data (newc stores it once, on the last link). `Ok(None)` = not in the archive.
pub fn cpio_file(archive: &[u8], names: &[&str]) -> Result<Option<Vec<u8>>, String> {
    let mut off = 0usize;
    let mut want_ino: Option<u64> = None;
    let mut best: Option<(usize, Vec<u8>)> = None;
    while off + 110 <= archive.len() {
        let h = &archive[off..off + 110];
        if &h[..6] != b"070701" && &h[..6] != b"070702" {
            return Err(format!("cpio: no newc header at offset {off}"));
        }
        let (ino, mode, nlink, size, namesize) = (hex_field(h, 0)?, hex_field(h, 1)?, hex_field(h, 4)?, hex_field(h, 6)? as usize, hex_field(h, 11)? as usize);
        let name_end = off + 110 + namesize;
        if namesize == 0 || name_end > archive.len() {
            return Err("cpio: truncated name".into());
        }
        let raw = &archive[off + 110..name_end - 1];
        let name = String::from_utf8_lossy(raw);
        let name = name.trim_start_matches("./").trim_start_matches('/');
        let data_at = pad4(name_end);
        let data_end = data_at.checked_add(size).filter(|e| *e <= archive.len()).ok_or("cpio: truncated file data")?;
        if name == "TRAILER!!!" {
            return Ok(best.map(|(_, d)| d));
        }
        let regular = mode & 0o170000 == 0o100000;
        let rank = names.iter().position(|n| *n == name);
        if regular {
            if let Some(r) = rank {
                if size > 0 && best.as_ref().is_none_or(|(b, _)| r < *b) {
                    best = Some((r, archive[data_at..data_end].to_vec()));
                } else if size == 0 && nlink > 1 {
                    want_ino = Some(ino);
                }
            } else if size > 0 && want_ino == Some(ino) && best.is_none() {
                // The data of a hard link named earlier with size 0.
                best = Some((names.len(), archive[data_at..data_end].to_vec()));
            }
        }
        off = pad4(data_end);
    }
    Err("cpio: truncated archive (no trailer)".into())
}

/// The agent packed into `img`'s initramfs (`/sbin/init`), checked against the sha256 the
/// image manifest recorded for it.
pub fn from_image(img: &GuestImage) -> Result<AgentBinary, String> {
    let path = img.initramfs();
    let f = std::fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut raw = Vec::new();
    flate2::read::MultiGzDecoder::new(f).take(MAX_INITRAMFS_BYTES).read_to_end(&mut raw).map_err(|e| format!("{}: not a gzip cpio archive: {e}", path.display()))?;
    let bytes = cpio_file(&raw, &["sbin/init", "usr/bin/seagent-vm-guest"])?.ok_or_else(|| format!("{}: no /sbin/init in the initramfs", path.display()))?;
    let a = AgentBinary::new(bytes, format!("guest image {}", img.dir.display()));
    let want = img.manifest.agent_sha256.trim();
    if !want.is_empty() && !want.eq_ignore_ascii_case(&a.sha256) {
        return Err(format!("{}: the agent's sha256 is {}, the image manifest says {want} (refusing it)", path.display(), a.sha256));
    }
    Ok(a)
}

/// Loose agent files (development builds), in order.
pub fn loose_candidates(data: &Path, exe: Option<&Path>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = exe.and_then(Path::parent).map(|d| d.join("seagent-vm-guest")).into_iter().collect();
    v.push(data.join("vm").join("seagent-vm-guest"));
    v
}

fn usable(a: &AgentBinary) -> Result<(), String> {
    if !is_x86_64_linux_elf(&a.bytes) {
        return Err(format!("{} is not an x86_64 Linux binary (the desktop VM is x86_64)", a.source));
    }
    if !has_service_role(&a.bytes) {
        return Err(format!("{} predates the desktop VM shell (no `service` role)", a.source));
    }
    Ok(())
}

/// The agent binary for the desktop VM (see the module docs for the order), or why none of
/// the places holds a usable one.
pub fn find(data: &Path) -> Result<AgentBinary, String> {
    find_in(data, std::env::current_exe().ok().as_deref())
}

pub fn find_in(data: &Path, exe: Option<&Path>) -> Result<AgentBinary, String> {
    let mut why = Vec::new();
    match GuestImage::find(&crate::VmConfig::default(), data).and_then(|img| from_image(&img)) {
        Ok(a) => match usable(&a) {
            Ok(()) => return Ok(a),
            Err(e) => why.push(e),
        },
        Err(e) => why.push(e.split("; run `").next().unwrap_or(&e).to_string()),
    }
    for p in loose_candidates(data, exe) {
        let Ok(meta) = std::fs::metadata(&p) else { continue };
        if !meta.is_file() || meta.len() > MAX_AGENT_BYTES {
            continue;
        }
        match std::fs::read(&p) {
            Ok(b) => {
                let a = AgentBinary::new(b, p.display().to_string());
                match usable(&a) {
                    Ok(()) => return Ok(a),
                    Err(e) => why.push(e),
                }
            }
            Err(e) => why.push(format!("read {}: {e}", p.display())),
        }
    }
    Err(format!("no guest agent for the desktop VM shell: {}", why.join("; ")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A newc archive of `(name, mode, ino, nlink, data)` entries.
    pub(crate) fn newc(entries: &[(&str, u32, u64, u64, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut push = |name: &str, mode: u32, ino: u64, nlink: u64, data: &[u8]| {
            let hdr = format!("070701{ino:08x}{mode:08x}{:08x}{:08x}{nlink:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}", 0, 0, 0, data.len(), 0, 0, 0, 0, name.len() + 1, 0);
            out.extend_from_slice(hdr.as_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out.extend_from_slice(data);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        };
        for (n, m, i, l, d) in entries {
            push(n, *m, *i, *l, d);
        }
        push("TRAILER!!!", 0, 0, 1, b"");
        out
    }

    /// Bytes that pass for an x86_64 agent with (or without) the service role.
    pub(crate) fn fake_agent(service: bool) -> Vec<u8> {
        let mut b = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
        b.extend_from_slice(b"...code...");
        if service {
            b.extend_from_slice(crate::proto::GUEST_ROLES.as_bytes());
        }
        b
    }

    #[test]
    fn the_agent_is_found_in_a_newc_archive_including_through_hard_links() {
        let agent = fake_agent(true);
        let a = newc(&[(".", 0o040755, 1, 2, b""), ("sbin", 0o040755, 2, 2, b""), ("bin/busybox", 0o100755, 3, 1, b"busybox"), ("./sbin/init", 0o100755, 4, 1, &agent)]);
        assert_eq!(cpio_file(&a, &["sbin/init"]).unwrap().as_deref(), Some(&agent[..]));
        assert_eq!(cpio_file(&a, &["usr/bin/nothing"]).unwrap(), None);
        // `sbin/init` and `usr/bin/seagent-vm-guest` as one inode: the data sits on the last link.
        let h = newc(&[("sbin/init", 0o100755, 9, 2, b""), ("usr/bin/seagent-vm-guest", 0o100755, 9, 2, &agent)]);
        assert_eq!(cpio_file(&h, &["sbin/init"]).unwrap().as_deref(), Some(&agent[..]));
        // A symlink named sbin/init (Alpine's busybox link) is not the agent.
        let l = newc(&[("sbin/init", 0o120777, 5, 1, b"/bin/busybox"), ("usr/bin/seagent-vm-guest", 0o100755, 6, 1, &agent)]);
        assert_eq!(cpio_file(&l, &["sbin/init", "usr/bin/seagent-vm-guest"]).unwrap().as_deref(), Some(&agent[..]));
        assert!(cpio_file(b"not a cpio archive at all, long enough to hold a header ......................................................", &["x"]).is_err());
        assert!(cpio_file(&a[..200], &["sbin/init"]).is_err(), "a truncated archive is an error, not a miss");
    }

    fn write_image(dir: &Path, agent: &[u8], recorded_sha: &str) {
        use std::io::Write as _;
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vmlinux"), b"kernel").unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&newc(&[("sbin/init", 0o100755, 1, 1, agent)])).unwrap();
        std::fs::write(dir.join("initramfs.cpio.gz"), gz.finish().unwrap()).unwrap();
        let entry = |p: &str| {
            let f = dir.join(p);
            serde_json::json!({"path": p, "sha256": crate::image::sha256_file(&f).unwrap(), "size": std::fs::metadata(&f).unwrap().len()})
        };
        let m = serde_json::json!({"image_version": crate::IMAGE_VERSION, "kernel": entry("vmlinux"), "initramfs": entry("initramfs.cpio.gz"), "agent": {"sha256": recorded_sha, "version": "test"}});
        std::fs::write(dir.join(crate::image::MANIFEST_FILE), m.to_string()).unwrap();
    }

    #[test]
    fn the_image_agent_is_verified_against_its_manifest_and_must_have_the_service_role() {
        let t = seagent_core::tmp::TempDir::new("seagent-dvm-agent");
        let data = t.join("data");
        let agent = fake_agent(true);
        let sha = seagent_net::crypto::hex(&seagent_net::crypto::sha256(&agent));
        write_image(&data.join("vm/image"), &agent, &sha);
        let got = find_in(&data, None).unwrap();
        assert_eq!((got.bytes.as_slice(), got.sha256.as_str()), (agent.as_slice(), sha.as_str()));
        assert!(got.source.contains("guest image"), "{}", got.source);
        // A manifest that records another agent: refused, never served to the VM.
        write_image(&data.join("vm/image"), &agent, &"0".repeat(64));
        let e = find_in(&data, None).unwrap_err();
        assert!(e.contains("manifest says"), "{e}");
        // An older agent in the image, a dev build next to the binary: the dev build is used.
        let old = fake_agent(false);
        write_image(&data.join("vm/image"), &old, &seagent_net::crypto::hex(&seagent_net::crypto::sha256(&old)));
        let bin = t.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("seagent-vm-guest"), &agent).unwrap();
        let got = find_in(&data, Some(&bin.join("seagent"))).unwrap();
        assert_eq!(got.source, bin.join("seagent-vm-guest").display().to_string());
        // Nothing usable anywhere: every reason is named.
        std::fs::write(bin.join("seagent-vm-guest"), b"MZ windows binary").unwrap();
        let e = find_in(&data, Some(&bin.join("seagent"))).unwrap_err();
        assert!(e.contains("predates the desktop VM shell") && e.contains("not an x86_64 Linux binary"), "{e}");
    }
}
