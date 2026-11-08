//! Workspace mirroring for backends that do not share the host file system
//! (SSH, Modal, Daytona, Vercel). The host workspace stays the source of truth:
//! `push` uploads what changed since the last cycle (mtime+size, deletions)
//! before a command, `pull` brings back what the command changed after it.
//! Both talk to the remote only through a `Runner` (run a bash script with
//! optional stdin, collect output), so any transport works; payloads are tar
//! archives, base64-wrapped when the transport cannot carry raw bytes.
//! Semantics follow Hermes tools/environments/file_sync.py (transactional
//! push, safe sync-back with a size cap), applied to the workspace.

#[path = "cloud_common.rs"]
pub mod common;

use seagent_core::exec::ExitInfo;
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

// Portable metadata for the manifest and the tar stream. Unix: the real mtime / mode, as
// before. Elsewhere: mtime from `modified()`, mode 0644 / 0755 (directories), read-only
// files 0444 — the fields stay, with the defaults a Unix receiver expects.
#[cfg(unix)]
fn mtime_of(m: &fs::Metadata) -> (i64, i64) {
    (m.mtime(), m.mtime_nsec())
}
#[cfg(not(unix))]
fn mtime_of(m: &fs::Metadata) -> (i64, i64) {
    let d = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos() as i64)
}
#[cfg(unix)]
fn mode_of(m: &fs::Metadata) -> u32 {
    m.mode()
}
#[cfg(not(unix))]
fn mode_of(m: &fs::Metadata) -> u32 {
    let base = if m.is_dir() { 0o755 } else { 0o644 };
    if m.permissions().readonly() {
        base & 0o555
    } else {
        base
    }
}
#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) {
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn set_mode(p: &Path, mode: u32) {
    // Only the write bit has a Windows meaning (the read-only attribute).
    if let Ok(m) = fs::metadata(p) {
        let mut perm = m.permissions();
        perm.set_readonly(mode & 0o222 == 0);
        let _ = fs::set_permissions(p, perm);
    }
}
#[cfg(unix)]
fn make_symlink(target: &str, dest: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, dest)
}
#[cfg(windows)]
fn make_symlink(target: &str, dest: &Path) -> std::io::Result<()> {
    // Needs Developer Mode or SeCreateSymbolicLinkPrivilege; the error says so if missing.
    std::os::windows::fs::symlink_file(target, dest)
}

/// Run `script` remotely with `stdin`, returning exit status and merged output.
pub type Runner<'a> = &'a dyn Fn(&str, Option<&[u8]>) -> Result<(ExitInfo, Vec<u8>), String>;

#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// Directory names never mirrored (anywhere in the tree).
    pub skip_dirs: Vec<String>,
    /// Refuse a push cycle uploading more than this.
    pub max_push_bytes: u64,
    /// Refuse a pull larger than this (Hermes `_SYNC_BACK_MAX_BYTES`, 2 GiB).
    pub max_pull_bytes: u64,
    /// Wrap tar payloads in base64 (transports with text-only stdin/stdout).
    pub base64: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions { skip_dirs: vec!["target".into(), "node_modules".into()], max_push_bytes: 1 << 30, max_pull_bytes: 2 << 30, base64: false }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SyncReport {
    pub uploaded: usize,
    pub deleted: usize,
    pub pulled: usize,
    pub bytes: u64,
    /// Entries left alone, with the reason (conflicts, unsafe paths, reset guard).
    pub skipped: Vec<String>,
}

type Key = (u64, i64, i64);

fn key_of(m: &fs::Metadata) -> Key {
    let (s, ns) = mtime_of(m);
    (m.len(), s, ns)
}

#[derive(Default)]
struct State {
    /// rel path → host key at the last successful push/pull.
    synced: HashMap<String, Key>,
    /// The remote stamp exists (a push completed).
    stamped: bool,
}

pub struct WorkspaceSync {
    host: PathBuf,
    remote: String,
    stamp: String,
    opts: SyncOptions,
    st: Mutex<State>,
}

impl WorkspaceSync {
    /// Mirror `host` (a directory) to `remote` (absolute path in the backend).
    pub fn new(host: &Path, remote: &str, opts: SyncOptions) -> WorkspaceSync {
        let tag = common::crc32(format!("{}|{remote}", host.display()).as_bytes());
        WorkspaceSync { host: host.to_path_buf(), remote: remote.trim_end_matches('/').to_string(), stamp: format!("/tmp/.seagent-sync-{tag:08x}.stamp"), opts, st: Mutex::new(State::default()) }
    }
    pub fn remote_root(&self) -> &str {
        &self.remote
    }

    /// Files to mirror: rel path → (absolute host path, metadata). Symlinks are kept as links.
    fn scan(&self) -> Vec<(String, PathBuf, fs::Metadata)> {
        let mut out = Vec::new();
        let mut stack = vec![self.host.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let Ok(m) = fs::symlink_metadata(&p) else { continue };
                let name = e.file_name().to_string_lossy().into_owned();
                if m.is_dir() {
                    if !self.opts.skip_dirs.contains(&name) {
                        stack.push(p);
                    }
                    continue;
                }
                if !(m.is_file() || m.file_type().is_symlink()) {
                    continue;
                }
                let Ok(rel) = p.strip_prefix(&self.host) else { continue };
                let rel = rel.to_string_lossy().into_owned();
                if rel.contains('\n') {
                    continue; // cannot travel through line-based remote listings
                }
                out.push((rel, p, m));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn payload(&self, tar: Vec<u8>) -> Vec<u8> {
        if self.opts.base64 {
            common::b64(&tar).into_bytes()
        } else {
            tar
        }
    }
    fn decoder(&self) -> &'static str {
        if self.opts.base64 {
            "base64 -d | "
        } else {
            ""
        }
    }

    /// Upload new/changed files and delete removed ones; then (re)stamp the remote.
    /// Transactional: state only advances when the remote command succeeded.
    pub fn push(&self, run: Runner) -> Result<SyncReport, String> {
        let mut st = self.st.lock().unwrap();
        let files = self.scan();
        let mut new_synced = HashMap::new();
        let mut tar = Tar::default();
        let mut rep = SyncReport::default();
        for (rel, path, m) in &files {
            let k = key_of(m);
            new_synced.insert(rel.clone(), k);
            if st.synced.get(rel) == Some(&k) {
                continue;
            }
            if m.file_type().is_symlink() {
                let target = fs::read_link(path).map_err(|e| format!("readlink {}: {e}", path.display()))?;
                tar.symlink(rel, &target.to_string_lossy(), mtime_of(&m).0);
            } else {
                rep.bytes += m.len();
                if rep.bytes > self.opts.max_push_bytes {
                    return Err(format!("workspace sync: more than {} bytes changed; refusing to upload (exclude large dirs or raise the limit)", self.opts.max_push_bytes));
                }
                let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
                tar.file(rel, &data, mode_of(&m) & 0o7777, mtime_of(&m).0);
            }
            rep.uploaded += 1;
        }
        let gone: Vec<&String> = st.synced.keys().filter(|k| !new_synced.contains_key(*k)).collect();
        rep.deleted = gone.len();
        if rep.uploaded == 0 && gone.is_empty() && st.stamped {
            return Ok(rep);
        }
        let root = crate::exec::sh_quote(&self.remote);
        let mut script = format!("set -e\nmkdir -p {root}\ncd {root}\n");
        for chunk in gone.chunks(200) {
            script.push_str("rm -f --");
            for g in chunk {
                script.push(' ');
                script.push_str(&crate::exec::sh_quote(g));
            }
            script.push('\n');
        }
        let stdin = if rep.uploaded > 0 {
            script.push_str(&format!("{}tar -xf - -C {root}\n", self.decoder()));
            Some(self.payload(tar.finish()))
        } else {
            None
        };
        script.push_str(&format!("touch {}\n", crate::exec::sh_quote(&self.stamp)));
        let (ex, out) = run(&script, stdin.as_deref())?;
        if !ex.success() {
            return Err(format!("workspace sync upload failed ({}): {}", ex.describe(), String::from_utf8_lossy(&out).trim()));
        }
        st.synced = new_synced;
        st.stamped = true;
        Ok(rep)
    }

    /// Bring back files the remote command created or changed (newer than the
    /// stamp) and files it deleted. A file the host changed meanwhile wins.
    pub fn pull(&self, run: Runner) -> Result<SyncReport, String> {
        let mut st = self.st.lock().unwrap();
        let mut rep = SyncReport::default();
        if !st.stamped {
            return Ok(rep);
        }
        let root = crate::exec::sh_quote(&self.remote);
        let stamp = crate::exec::sh_quote(&self.stamp);
        let prune: String = self.opts.skip_dirs.iter().map(|d| format!(" -name {} -prune -o", crate::exec::sh_quote(d))).collect();
        let list = format!(
            "cd {root} 2>/dev/null || {{ echo __ARK_NOROOT__; exit 0; }}\n[ -e {stamp} ] || {{ echo __ARK_NOSTAMP__; exit 0; }}\n\
find . -mindepth 1 -type d \\({prune} -false \\) -o \\( -type f -o -type l \\) -newer {stamp} -printf 'N\\t%P\\n' -o \\( -type f -o -type l \\) -printf 'O\\t%P\\n' 2>/dev/null\n"
        );
        let (ex, out) = run(&list, None)?;
        if !ex.success() {
            return Err(format!("workspace sync listing failed ({}): {}", ex.describe(), String::from_utf8_lossy(&out).trim()));
        }
        let text = String::from_utf8_lossy(&out);
        if text.contains("__ARK_NOROOT__") || text.contains("__ARK_NOSTAMP__") {
            rep.skipped.push("remote workspace or sync stamp missing (sandbox recreated?); nothing pulled".into());
            st.stamped = false;
            st.synced.clear();
            return Ok(rep);
        }
        let mut remote_all = std::collections::HashSet::new();
        let mut newer = Vec::new();
        for l in text.lines() {
            let Some((tag, rel)) = l.split_once('\t') else { continue };
            remote_all.insert(rel.to_string());
            if tag == "N" {
                newer.push(rel.to_string());
            }
        }
        // Deletions made remotely.
        let deleted: Vec<String> = st.synced.keys().filter(|k| !remote_all.contains(*k)).cloned().collect();
        if deleted.len() > 20 && deleted.len() * 2 > st.synced.len() {
            rep.skipped.push(format!("{} of {} files vanished remotely; looks like a reset workspace, not deleting them on the host", deleted.len(), st.synced.len()));
        } else {
            for rel in deleted {
                let p = self.host.join(&rel);
                match fs::symlink_metadata(&p) {
                    Ok(m) if st.synced.get(&rel) == Some(&key_of(&m)) && safe_host_path(&self.host, &rel).is_some() => {
                        if fs::remove_file(&p).is_ok() {
                            rep.deleted += 1;
                        }
                        st.synced.remove(&rel);
                    }
                    Ok(_) => rep.skipped.push(format!("{rel}: deleted remotely but changed on the host; kept")),
                    Err(_) => {
                        st.synced.remove(&rel);
                    }
                }
            }
        }
        let mut stdin = newer.join("\n").into_bytes();
        stdin.push(b'\n');
        let enc = if self.opts.base64 { " | base64" } else { "" };
        let script = if newer.is_empty() { format!("touch {stamp}\n") } else { format!("cd {root} && tar -cf - -T -{enc}; s=$?; touch {stamp}; exit $s\n") };
        let (ex, out) = run(&script, (!newer.is_empty()).then_some(&stdin[..]))?;
        if !ex.success() {
            return Err(format!("workspace sync download failed ({}): {}", ex.describe(), String::from_utf8_lossy(&out).chars().take(300).collect::<String>()));
        }
        if newer.is_empty() {
            return Ok(rep);
        }
        let raw = if self.opts.base64 { common::unb64(&out)? } else { out };
        let entries = read_tar(&raw)?;
        let total: u64 = entries.iter().map(|e| e.data.len() as u64).sum();
        if total > self.opts.max_pull_bytes {
            return Err(format!("workspace sync: remote changes total {total} bytes, over the {} byte limit; nothing applied", self.opts.max_pull_bytes));
        }
        for e in entries {
            let rel = e.path.trim_start_matches("./").to_string();
            let Some(dest) = safe_host_path(&self.host, &rel) else {
                rep.skipped.push(format!("{}: unsafe path in remote archive; ignored", e.path));
                continue;
            };
            let cur = fs::symlink_metadata(&dest).ok();
            if let Some(m) = &cur {
                if let Some(k) = st.synced.get(&rel) {
                    if *k != key_of(m) {
                        rep.skipped.push(format!("{rel}: changed both on the host and remotely; host copy kept"));
                        continue;
                    }
                }
                if m.is_dir() {
                    rep.skipped.push(format!("{rel}: is a directory on the host; ignored"));
                    continue;
                }
            }
            if let Some(d) = dest.parent() {
                fs::create_dir_all(d).map_err(|err| format!("create {}: {err}", d.display()))?;
            }
            match e.kind {
                b'2' => {
                    if !link_stays_inside(&rel, &e.link) {
                        rep.skipped.push(format!("{rel}: symlink to {} leaves the workspace; ignored", e.link));
                        continue;
                    }
                    let _ = fs::remove_file(&dest);
                    make_symlink(&e.link, &dest).map_err(|err| format!("symlink {}: {err}", dest.display()))?;
                }
                b'0' => {
                    if cur.as_ref().is_some_and(|m| m.is_file()) && fs::read(&dest).ok().as_deref() == Some(&e.data[..]) {
                        if let Ok(m) = fs::symlink_metadata(&dest) {
                            st.synced.insert(rel.clone(), key_of(&m));
                        }
                        continue;
                    }
                    if cur.as_ref().is_some_and(|m| m.file_type().is_symlink()) {
                        let _ = fs::remove_file(&dest);
                    }
                    crate::util::atomic_write(&dest, &e.data).map_err(|err| format!("write {}: {err}", dest.display()))?;
                    set_mode(&dest, e.mode & 0o777);
                    rep.bytes += e.data.len() as u64;
                }
                _ => continue,
            }
            rep.pulled += 1;
            if let Ok(m) = fs::symlink_metadata(&dest) {
                st.synced.insert(rel, key_of(&m));
            }
        }
        Ok(rep)
    }

    /// Forget all state: the next push re-uploads everything (sandbox recreated).
    pub fn reset(&self) {
        *self.st.lock().unwrap() = State::default();
    }
}

/// Host files that only go *to* the sandbox (Hermes credential_files): `~/x`
/// lands at `$HOME/x` remotely, an absolute path at the same path. Paths that
/// expose seagent's own data or private keys of other tools are refused by the caller's
/// policy; here we refuse non-files. Returns how many were uploaded.
pub fn upload_files(run: Runner, files: &[String], base64: bool) -> Result<usize, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let mut home_tar = Tar::default();
    let mut abs_tar = Tar::default();
    let (mut nh, mut na) = (0, 0);
    for f in files {
        let host = seagent_core::tool::expand_home(f);
        let m = fs::metadata(&host).map_err(|e| format!("credential file {f}: {e}"))?;
        if !m.is_file() {
            return Err(format!("credential file {f} is not a regular file"));
        }
        let data = fs::read(&host).map_err(|e| format!("credential file {f}: {e}"))?;
        match host.strip_prefix(&home) {
            Ok(rel) if !home.as_os_str().is_empty() => {
                home_tar.file(&rel.to_string_lossy(), &data, 0o600, mtime_of(&m).0);
                nh += 1;
            }
            _ => {
                abs_tar.file(host.to_string_lossy().trim_start_matches('/'), &data, 0o600, mtime_of(&m).0);
                na += 1;
            }
        }
    }
    let dec = if base64 { "base64 -d | " } else { "" };
    for (n, tar, dest) in [(nh, home_tar, "\"$HOME\""), (na, abs_tar, "/")] {
        if n == 0 {
            continue;
        }
        let raw = tar.finish();
        let payload = if base64 { common::b64(&raw).into_bytes() } else { raw };
        let (ex, out) = run(&format!("umask 077; {dec}tar -xf - -C {dest}\n"), Some(&payload))?;
        if !ex.success() {
            return Err(format!("credential upload failed ({}): {}", ex.describe(), String::from_utf8_lossy(&out).trim()));
        }
    }
    Ok(nh + na)
}

/// `rel` as a host path under `root`, refusing absolute paths, `..`, and paths
/// whose existing ancestors are symlinks (a remote archive must not write outside).
pub fn safe_host_path(root: &Path, rel: &str) -> Option<PathBuf> {
    let p = Path::new(rel);
    if rel.is_empty() || p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    let mut cur = root.to_path_buf();
    let comps: Vec<_> = p.components().collect();
    for (i, c) in comps.iter().enumerate() {
        cur.push(c);
        if i + 1 < comps.len() {
            if let Ok(m) = fs::symlink_metadata(&cur) {
                if m.file_type().is_symlink() || !m.is_dir() {
                    return None;
                }
            }
        }
    }
    Some(cur)
}

/// A relative symlink at `rel` pointing to `target` stays inside the root.
fn link_stays_inside(rel: &str, target: &str) -> bool {
    if target.starts_with('/') || target.is_empty() {
        return false;
    }
    let mut depth: i64 = Path::new(rel).components().count() as i64 - 1;
    for c in Path::new(target).components() {
        match c {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            _ => return false,
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

// ───────────── tar (ustar + pax / GNU long names) ─────────────

#[derive(Default)]
pub struct Tar {
    buf: Vec<u8>,
}

fn octal(field: &mut [u8], v: u64) {
    let s = format!("{:0w$o}", v, w = field.len() - 1);
    field[..s.len()].copy_from_slice(s.as_bytes());
    field[s.len()] = 0;
}

impl Tar {
    fn header(&mut self, name: &str, kind: u8, size: u64, mode: u32, mtime: i64, link: &str) {
        let mut pax = String::new();
        if name.len() > 99 {
            pax.push_str(&pax_record("path", name));
        }
        if link.len() > 99 {
            pax.push_str(&pax_record("linkpath", link));
        }
        if !pax.is_empty() {
            let short = format!("PaxHeaders/{}", name.chars().rev().take(60).collect::<String>().chars().rev().collect::<String>());
            self.raw_header(&short, b'x', pax.len() as u64, 0o644, mtime, "");
            self.buf.extend_from_slice(pax.as_bytes());
            self.pad();
        }
        self.raw_header(name, kind, size, mode, mtime, link);
    }
    fn raw_header(&mut self, name: &str, kind: u8, size: u64, mode: u32, mtime: i64, link: &str) {
        let mut h = [0u8; 512];
        let n = name.as_bytes();
        h[..n.len().min(99)].copy_from_slice(&n[..n.len().min(99)]);
        octal(&mut h[100..108], mode as u64);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], size);
        octal(&mut h[136..148], mtime.max(0) as u64);
        h[156] = kind;
        let l = link.as_bytes();
        h[157..157 + l.len().min(99)].copy_from_slice(&l[..l.len().min(99)]);
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        self.buf.extend_from_slice(&h);
    }
    fn pad(&mut self) {
        let r = self.buf.len() % 512;
        if r != 0 {
            self.buf.resize(self.buf.len() + 512 - r, 0);
        }
    }
    pub fn file(&mut self, name: &str, data: &[u8], mode: u32, mtime: i64) {
        self.header(name, b'0', data.len() as u64, mode, mtime, "");
        self.buf.extend_from_slice(data);
        self.pad();
    }
    pub fn symlink(&mut self, name: &str, target: &str, mtime: i64) {
        self.header(name, b'2', 0, 0o777, mtime, target);
    }
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.extend_from_slice(&[0u8; 1024]);
        self.buf
    }
}

fn pax_record(k: &str, v: &str) -> String {
    // "<len> k=v\n" where len counts itself.
    let body = format!(" {k}={v}\n");
    let mut len = body.len() + 1;
    while format!("{len}").len() + body.len() != len {
        len += 1;
    }
    format!("{len}{body}")
}

pub struct TarEntry {
    pub path: String,
    /// b'0' file, b'2' symlink, b'5' dir.
    pub kind: u8,
    pub mode: u32,
    pub link: String,
    pub data: Vec<u8>,
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn parse_num(b: &[u8]) -> u64 {
    if b.first().is_some_and(|c| c & 0x80 != 0) {
        // GNU base-256.
        return b[1..].iter().fold(0u64, |a, &c| a << 8 | c as u64);
    }
    let s = cstr(b);
    u64::from_str_radix(s.trim().trim_end_matches('\0'), 8).unwrap_or(0)
}

/// Parse a tar archive (ustar, pax `x`, GNU `L`/`K` long names).
pub fn read_tar(raw: &[u8]) -> Result<Vec<TarEntry>, String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let (mut long_name, mut long_link): (Option<String>, Option<String>) = (None, None);
    while off + 512 <= raw.len() {
        let h = &raw[off..off + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let size = parse_num(&h[124..136]) as usize;
        let kind = h[156];
        let start = off + 512;
        let end = start.checked_add(size).filter(|e| *e <= raw.len()).ok_or("truncated tar archive")?;
        let data = &raw[start..end];
        off = start + size.div_ceil(512) * 512;
        let mut name = cstr(&h[0..100]);
        if &h[257..262] == b"ustar" {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        match kind {
            b'L' => {
                long_name = Some(cstr(data));
                continue;
            }
            b'K' => {
                long_link = Some(cstr(data));
                continue;
            }
            b'x' => {
                let text = String::from_utf8_lossy(data);
                for rec in text.split_inclusive('\n') {
                    if let Some((_, kv)) = rec.split_once(' ') {
                        if let Some((k, v)) = kv.trim_end_matches('\n').split_once('=') {
                            match k {
                                "path" => long_name = Some(v.to_string()),
                                "linkpath" => long_link = Some(v.to_string()),
                                _ => {}
                            }
                        }
                    }
                }
                continue;
            }
            b'g' => continue,
            _ => {}
        }
        let path = long_name.take().unwrap_or(name);
        let link = long_link.take().unwrap_or_else(|| cstr(&h[157..257]));
        let kind = if kind == 0 || kind == b'7' { b'0' } else { kind };
        out.push(TarEntry { path, kind, mode: parse_num(&h[100..108]) as u32, link, data: data.to_vec() });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tmpdir;
    use std::process::{Command, Stdio};

    /// "Remote" = real bash on this machine, so tar/find/base64 are the real tools.
    fn local_runner(script: &str, stdin: Option<&[u8]>) -> Result<(ExitInfo, Vec<u8>), String> {
        use std::io::Write;
        let mut c = Command::new("bash").arg("-c").arg(script).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
        let mut si = c.stdin.take().unwrap();
        let data = stdin.unwrap_or_default().to_vec();
        let w = std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
        let o = c.wait_with_output().map_err(|e| e.to_string())?;
        let _ = w.join();
        let mut out = o.stdout;
        if !o.status.success() {
            out.extend_from_slice(&o.stderr);
        }
        Ok((ExitInfo { code: o.status.code(), signal: None }, out))
    }

    #[test]
    fn tar_roundtrip_with_long_names_and_links() {
        let mut t = Tar::default();
        let long = format!("{}/file.txt", "d".repeat(150));
        t.file("a.txt", b"hello", 0o644, 1_700_000_000);
        t.file(&long, b"x", 0o600, 1);
        t.symlink("l", &"t".repeat(120), 1);
        let raw = t.finish();
        let e = read_tar(&raw).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!((e[0].path.as_str(), e[0].data.as_slice(), e[0].mode), ("a.txt", &b"hello"[..], 0o644));
        assert_eq!(e[1].path, long);
        assert_eq!((e[2].kind, e[2].link.len()), (b'2', 120));
        // GNU tar reads ours.
        let d = tmpdir("tarx");
        std::fs::write(d.join("in.tar"), &raw).unwrap();
        let ok = Command::new("tar").arg("-xf").arg(d.join("in.tar")).arg("-C").arg(&d).status().unwrap();
        assert!(ok.success());
        assert_eq!(std::fs::read_to_string(d.join(&long)).unwrap(), "x");
        assert!(read_tar(&raw[..514]).is_err(), "data cut short");
    }

    #[cfg(unix)]
    #[test]
    fn path_safety() {
        let d = tmpdir("safep");
        assert!(safe_host_path(&d, "a/b.txt").is_some());
        assert!(safe_host_path(&d, "../x").is_none());
        assert!(safe_host_path(&d, "/etc/passwd").is_none());
        assert!(safe_host_path(&d, "a/./b").is_some(), "Path normalises `.` away");
        std::os::unix::fs::symlink("/tmp", d.join("esc")).unwrap();
        assert!(safe_host_path(&d, "esc/x").is_none(), "through a symlinked dir");
        assert!(link_stays_inside("a/b", "../c") && !link_stays_inside("a", "../../x") && !link_stays_inside("a", "/etc"));
    }

    #[cfg(unix)]
    fn mirror(tag: &str, base64: bool) {
        let host = tmpdir(&format!("{tag}h"));
        let remote = tmpdir(&format!("{tag}r")).join("ws");
        std::fs::create_dir_all(host.join("src")).unwrap();
        std::fs::create_dir_all(host.join("target")).unwrap();
        std::fs::write(host.join("src/a.txt"), "one").unwrap();
        std::fs::write(host.join("del.txt"), "bye").unwrap();
        std::fs::write(host.join("target/big.o"), "skip").unwrap();
        std::os::unix::fs::symlink("src/a.txt", host.join("link")).unwrap();
        let s = WorkspaceSync::new(&host, &remote.to_string_lossy(), SyncOptions { base64, ..Default::default() });
        let r = s.push(&local_runner).unwrap();
        assert_eq!((r.uploaded, r.deleted), (3, 0));
        assert_eq!(std::fs::read_to_string(remote.join("src/a.txt")).unwrap(), "one");
        assert!(!remote.join("target").exists(), "skip dirs");
        assert_eq!(std::fs::read_link(remote.join("link")).unwrap(), Path::new("src/a.txt"));
        assert_eq!(s.push(&local_runner).unwrap().uploaded, 0, "unchanged → nothing");
        std::fs::remove_file(host.join("del.txt")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(host.join("src/a.txt"), "two").unwrap();
        let r = s.push(&local_runner).unwrap();
        assert_eq!((r.uploaded, r.deleted), (1, 1));
        assert!(!remote.join("del.txt").exists());
        assert_eq!(std::fs::read_to_string(remote.join("src/a.txt")).unwrap(), "two");

        // The "command" changes things remotely.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(remote.join("new.txt"), "made remotely").unwrap();
        std::fs::write(remote.join("src/a.txt"), "three").unwrap();
        std::fs::remove_file(remote.join("link")).unwrap();
        std::fs::create_dir_all(remote.join("node_modules")).unwrap();
        std::fs::write(remote.join("node_modules/x.js"), "skip").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", remote.join("evil")).unwrap();
        let r = s.pull(&local_runner).unwrap();
        assert_eq!(std::fs::read_to_string(host.join("new.txt")).unwrap(), "made remotely");
        assert_eq!(std::fs::read_to_string(host.join("src/a.txt")).unwrap(), "three");
        assert!(!host.join("link").exists(), "remote deletion applied");
        assert!(!host.join("node_modules").exists());
        assert!(!host.join("evil").exists() && r.skipped.iter().any(|x| x.contains("leaves the workspace")), "{r:?}");
        assert_eq!(r.deleted, 1);
        // Pulled files are not pushed back.
        assert_eq!(s.push(&local_runner).unwrap().uploaded, 0);

        // Conflict: both sides change → host wins.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(remote.join("new.txt"), "remote edit").unwrap();
        std::fs::write(host.join("new.txt"), "host edit").unwrap();
        let r = s.pull(&local_runner).unwrap();
        assert_eq!(std::fs::read_to_string(host.join("new.txt")).unwrap(), "host edit");
        assert!(r.skipped.iter().any(|x| x.contains("host copy kept")), "{r:?}");
    }

    #[cfg(unix)]
    #[test]
    fn push_pull_mirror_raw() {
        mirror("syncraw", false);
    }

    #[cfg(unix)]
    #[test]
    fn push_pull_mirror_base64() {
        mirror("sync64", true);
    }

    #[test]
    fn reset_guard_and_missing_stamp() {
        let host = tmpdir("syncguard");
        for i in 0..30 {
            std::fs::write(host.join(format!("f{i}")), "x").unwrap();
        }
        let remote = tmpdir("syncguardr").join("ws");
        let s = WorkspaceSync::new(&host, &remote.to_string_lossy(), SyncOptions::default());
        s.push(&local_runner).unwrap();
        for i in 0..25 {
            std::fs::remove_file(remote.join(format!("f{i}"))).unwrap();
        }
        let r = s.pull(&local_runner).unwrap();
        assert!(r.skipped.iter().any(|x| x.contains("reset workspace")) && host.join("f0").exists());
        std::fs::remove_dir_all(&remote).unwrap();
        let r = s.pull(&local_runner).unwrap();
        assert!(r.skipped[0].contains("missing"));
        assert_eq!(s.push(&local_runner).unwrap().uploaded, 30, "re-uploads everything after a reset");
        let small = WorkspaceSync::new(&host, &remote.to_string_lossy(), SyncOptions { max_push_bytes: 5, ..Default::default() });
        assert!(small.push(&local_runner).unwrap_err().contains("refusing"));
    }

    #[cfg(unix)]
    #[test]
    fn credential_files_land_under_remote_home() {
        let _lock = crate::exec::sync::common::fakecli::lock_path();
        let fakehome = tmpdir("credhome");
        let hosthome = tmpdir("credrealhome");
        std::fs::create_dir_all(&hosthome).unwrap();
        let src = hosthome.join(format!(".seagent-cred-test-{}", std::process::id()));
        std::fs::write(&src, "token=1").unwrap();
        let runner = |script: &str, stdin: Option<&[u8]>| local_runner(&format!("export HOME={}\n{script}", fakehome.display()), stdin);
        let rel = format!("~/{}", src.file_name().unwrap().to_string_lossy());
        {
            let _home = crate::testutil::test_home(&hosthome);
            assert_eq!(upload_files(&runner, &[rel], true).unwrap(), 1);
            assert!(upload_files(&runner, &["/nonexistent/x".into()], false).is_err());
            assert!(upload_files(&runner, &["/tmp".into()], false).unwrap_err().contains("not a regular file"));
        }
        let got = fakehome.join(src.file_name().unwrap());
        assert_eq!(std::fs::read_to_string(&got).unwrap(), "token=1");
        assert_eq!(std::fs::metadata(&got).unwrap().mode() & 0o777, 0o600);
        let _ = std::fs::remove_file(&src);
    }
}
