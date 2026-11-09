//! WASI preview 1 (`wasi_snapshot_preview1`) for the `wasm` exec backend, written against
//! wasmi's linker. Only what a POSIX tool compiled for `wasm32-wasip1` needs: args, environ,
//! clocks, random, stdio, files and directories under the preopened roots, `poll_oneoff`
//! sleeps, `proc_exit`. There is no way to open a socket in preview 1 and none is offered
//! (`sock_*` answer ENOTSUP), so a tool has no network at all.
//!
//! Confinement is checked here, on the host side, for every path: the path is joined to its
//! directory descriptor lexically (a `..` that would leave the preopened root is refused), the
//! deepest existing ancestor is canonicalised and must still lie inside that root (a symlink
//! cannot point a tool outside), and anything that writes needs a writable root — the same
//! read / write-root policy the bwrap, Landlock, Seatbelt and AppContainer backends apply,
//! enforced by the interpreter instead of the kernel.

use super::policy::Root;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wasmi::{Caller, Error, Linker};

/// WASI errno values (preview 1 numbering).
pub mod errno {
    pub const SUCCESS: u16 = 0;
    pub const ACCES: u16 = 2;
    pub const BADF: u16 = 8;
    pub const EXIST: u16 = 20;
    pub const FAULT: u16 = 21;
    pub const INVAL: u16 = 28;
    pub const IO: u16 = 29;
    pub const ISDIR: u16 = 31;
    pub const LOOP: u16 = 32;
    pub const NAMETOOLONG: u16 = 37;
    pub const NOENT: u16 = 44;
    pub const NOSPC: u16 = 51;
    pub const NOSYS: u16 = 52;
    pub const NOTDIR: u16 = 54;
    pub const NOTEMPTY: u16 = 55;
    pub const NOTSUP: u16 = 58;
    pub const PERM: u16 = 63;
    pub const ROFS: u16 = 69;
    pub const SPIPE: u16 = 70;
    pub const XDEV: u16 = 75;
    pub const NOTCAPABLE: u16 = 76;
}
use errno::*;

const FT_UNKNOWN: u8 = 0;
const FT_CHAR: u8 = 2;
const FT_DIR: u8 = 3;
const FT_FILE: u8 = 4;
const FT_SYMLINK: u8 = 7;

const O_CREAT: u16 = 1;
const O_DIRECTORY: u16 = 2;
const O_EXCL: u16 = 4;
const O_TRUNC: u16 = 8;
const FDFLAG_APPEND: u16 = 1;
const LOOKUP_FOLLOW: u32 = 1;
const RIGHT_FD_READ: u64 = 1 << 1;
const RIGHT_FD_WRITE: u64 = 1 << 6;
const RIGHTS_ALL: u64 = (1 << 30) - 1;

type R<T> = Result<T, u16>;

/// One open descriptor.
pub enum Fd {
    In(Box<dyn Read + Send>),
    Out(Box<dyn Write + Send>),
    File { f: File, write: bool, append: bool },
    Dir { host: PathBuf, root: usize, guest: Option<String> },
}

/// The store data of one running tool.
pub struct Proc {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub fds: Vec<Option<Fd>>,
    pub roots: Arc<Vec<Root>>,
    pub kill: Arc<AtomicBool>,
    pub limits: wasmi::StoreLimits,
}

impl Proc {
    /// fd 0–2 are the given streams, fd 3… one per root (the preopens), then `.` = `cwd`.
    pub fn new(args: Vec<String>, env: Vec<(String, String)>, roots: Arc<Vec<Root>>, cwd: Option<(PathBuf, usize)>, stdio: (Box<dyn Read + Send>, Box<dyn Write + Send>, Box<dyn Write + Send>), kill: Arc<AtomicBool>, memory_bytes: usize) -> Proc {
        let mut fds = vec![Some(Fd::In(stdio.0)), Some(Fd::Out(stdio.1)), Some(Fd::Out(stdio.2))];
        for (i, r) in roots.iter().enumerate() {
            fds.push(Some(Fd::Dir { host: r.host.clone(), root: i, guest: Some(r.guest.clone()) }));
        }
        if let Some((host, root)) = cwd {
            fds.push(Some(Fd::Dir { host, root, guest: Some(".".into()) }));
        }
        let limits = wasmi::StoreLimitsBuilder::new().memory_size(memory_bytes).instances(4).memories(1).tables(8).build();
        Proc { args, env, fds, roots, kill, limits }
    }

    fn fd(&mut self, fd: u32) -> R<&mut Fd> {
        self.fds.get_mut(fd as usize).and_then(|f| f.as_mut()).ok_or(BADF)
    }

    fn dir(&self, fd: u32) -> R<(PathBuf, usize)> {
        match self.fds.get(fd as usize).and_then(|f| f.as_ref()) {
            Some(Fd::Dir { host, root, .. }) => Ok((host.clone(), *root)),
            Some(_) => Err(NOTDIR),
            None => Err(BADF),
        }
    }

    fn insert(&mut self, f: Fd) -> u32 {
        if let Some(i) = self.fds.iter().position(|x| x.is_none()) {
            self.fds[i] = Some(f);
            return i as u32;
        }
        self.fds.push(Some(f));
        (self.fds.len() - 1) as u32
    }

    /// `dirfd` + relative `path` → a confined host path (see the module docs).
    fn resolve(&self, dirfd: u32, path: &str, follow: bool, write: bool) -> R<(PathBuf, usize)> {
        let (base, root) = self.dir(dirfd)?;
        let r = &self.roots[root];
        if write && !r.write {
            return Err(ROFS);
        }
        let p = confine(&r.host, &base, path, follow)?;
        Ok((p, root))
    }
}

/// Join `rel` to `base` lexically, staying inside `root`, then make sure no symlink on the
/// way leads outside it. `follow`: a final symlink is resolved (and must stay inside too).
pub fn confine(root: &Path, base: &Path, rel: &str, follow: bool) -> R<PathBuf> {
    if rel.contains('\0') {
        return Err(INVAL);
    }
    if rel.len() > 4096 {
        return Err(NAMETOOLONG);
    }
    let mut out = base.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            Component::RootDir | Component::Prefix(_) => return Err(NOTCAPABLE),
            Component::CurDir => {}
            Component::ParentDir => {
                if out == root || !out.pop() || !out.starts_with(root) {
                    return Err(NOTCAPABLE);
                }
            }
            Component::Normal(n) => out.push(n),
        }
    }
    if !out.starts_with(root) {
        return Err(NOTCAPABLE);
    }
    // Every existing ancestor must canonicalise to somewhere inside the root.
    let mut probe = out.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let last_is_link = std::fs::symlink_metadata(&out).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    if last_is_link && !follow {
        // The link itself is the object (unlink, readlink, lstat): its parent must be inside.
        let parent = out.parent().ok_or(NOTCAPABLE)?;
        let cp = parent.canonicalize().map_err(|e| from_io(&e))?;
        if !cp.starts_with(root) {
            return Err(NOTCAPABLE);
        }
        return Ok(cp.join(out.file_name().ok_or(INVAL)?));
    }
    loop {
        match probe.canonicalize() {
            Ok(c) => {
                if !c.starts_with(root) {
                    return Err(NOTCAPABLE);
                }
                let mut p = c;
                for t in tail.iter().rev() {
                    p.push(t);
                }
                return Ok(p);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // A dangling symlink is not followed out of the sandbox.
                if std::fs::symlink_metadata(&probe).is_ok() {
                    return Err(NOTCAPABLE);
                }
                let name = probe.file_name().ok_or(NOTCAPABLE)?.to_os_string();
                tail.push(name);
                if !probe.pop() || !probe.starts_with(root) {
                    return Err(NOTCAPABLE);
                }
            }
            Err(e) => return Err(from_io(&e)),
        }
    }
}

/// io::Error → WASI errno.
pub fn from_io(e: &io::Error) -> u16 {
    #[cfg(unix)]
    if let Some(n) = e.raw_os_error() {
        return match n {
            libc::ENOENT => NOENT,
            libc::EACCES => ACCES,
            libc::EPERM => PERM,
            libc::EEXIST => EXIST,
            libc::ENOTDIR => NOTDIR,
            libc::EISDIR => ISDIR,
            libc::ENOTEMPTY => NOTEMPTY,
            libc::EXDEV => XDEV,
            libc::ELOOP => LOOP,
            libc::ENAMETOOLONG => NAMETOOLONG,
            libc::EINVAL => INVAL,
            libc::ENOSPC => NOSPC,
            libc::EROFS => ROFS,
            libc::EBADF => BADF,
            libc::ESPIPE => SPIPE,
            _ => IO,
        };
    }
    match e.kind() {
        io::ErrorKind::NotFound => NOENT,
        io::ErrorKind::PermissionDenied => ACCES,
        io::ErrorKind::AlreadyExists => EXIST,
        io::ErrorKind::InvalidInput => INVAL,
        io::ErrorKind::DirectoryNotEmpty => NOTEMPTY,
        io::ErrorKind::IsADirectory => ISDIR,
        io::ErrorKind::NotADirectory => NOTDIR,
        io::ErrorKind::ReadOnlyFilesystem => ROFS,
        _ => IO,
    }
}

// ───────────── guest memory ─────────────

fn mem_of(c: &Caller<'_, Proc>) -> Result<wasmi::Memory, Error> {
    c.get_export("memory").and_then(|e| e.into_memory()).ok_or_else(|| Error::new("wasi: the module exports no memory"))
}

fn split<'a>(c: &'a mut Caller<'_, Proc>) -> Result<(&'a mut [u8], &'a mut Proc), Error> {
    let m = mem_of(c)?;
    Ok(m.data_and_store_mut(c))
}

fn slice(m: &[u8], p: u32, n: u32) -> R<&[u8]> {
    let (p, n) = (p as usize, n as usize);
    m.get(p..p.checked_add(n).ok_or(FAULT)?).ok_or(FAULT)
}

fn put(m: &mut [u8], p: u32, b: &[u8]) -> R<()> {
    let p = p as usize;
    m.get_mut(p..p.checked_add(b.len()).ok_or(FAULT)?).ok_or(FAULT)?.copy_from_slice(b);
    Ok(())
}

fn u32_at(m: &[u8], p: u32) -> R<u32> {
    Ok(u32::from_le_bytes(slice(m, p, 4)?.try_into().map_err(|_| FAULT)?))
}

fn u64_at(m: &[u8], p: u32) -> R<u64> {
    Ok(u64::from_le_bytes(slice(m, p, 8)?.try_into().map_err(|_| FAULT)?))
}

fn put32(m: &mut [u8], p: u32, v: u32) -> R<()> {
    put(m, p, &v.to_le_bytes())
}

fn put64(m: &mut [u8], p: u32, v: u64) -> R<()> {
    put(m, p, &v.to_le_bytes())
}

fn path_arg(m: &[u8], p: u32, n: u32) -> R<String> {
    String::from_utf8(slice(m, p, n)?.to_vec()).map_err(|_| INVAL)
}

/// (ptr, len) pairs of an iovec array.
fn iovecs(m: &[u8], p: u32, n: u32) -> R<Vec<(u32, u32)>> {
    (0..n).map(|i| Ok((u32_at(m, p + i * 8)?, u32_at(m, p + i * 8 + 4)?))).collect()
}

fn done(r: R<()>) -> Result<i32, Error> {
    Ok(match r {
        Ok(()) => SUCCESS as i32,
        Err(e) => e as i32,
    })
}

// ───────────── stat helpers ─────────────

fn ftype(ft: std::fs::FileType) -> u8 {
    if ft.is_dir() {
        FT_DIR
    } else if ft.is_file() {
        FT_FILE
    } else if ft.is_symlink() {
        FT_SYMLINK
    } else {
        FT_UNKNOWN
    }
}

fn nanos(t: io::Result<SystemTime>) -> u64 {
    t.ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// The 64-byte `filestat`.
fn filestat(md: &std::fs::Metadata) -> [u8; 64] {
    let mut b = [0u8; 64];
    #[cfg(unix)]
    let (dev, ino, nlink) = {
        use std::os::unix::fs::MetadataExt;
        (md.dev(), md.ino(), md.nlink())
    };
    #[cfg(not(unix))]
    let (dev, ino, nlink) = (0u64, 0u64, 1u64);
    b[0..8].copy_from_slice(&dev.to_le_bytes());
    b[8..16].copy_from_slice(&ino.to_le_bytes());
    b[16] = ftype(md.file_type());
    b[24..32].copy_from_slice(&nlink.to_le_bytes());
    b[32..40].copy_from_slice(&md.len().to_le_bytes());
    b[40..48].copy_from_slice(&nanos(md.accessed()).to_le_bytes());
    b[48..56].copy_from_slice(&nanos(md.modified()).to_le_bytes());
    b[56..64].copy_from_slice(&nanos(md.modified()).to_le_bytes());
    b
}

fn char_filestat() -> [u8; 64] {
    let mut b = [0u8; 64];
    b[16] = FT_CHAR;
    b[24..32].copy_from_slice(&1u64.to_le_bytes());
    b
}

fn monotonic_ns() -> u64 {
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

fn killed(p: &Proc) -> bool {
    p.kill.load(Ordering::SeqCst)
}

/// A host trap that ends the run like SIGKILL would.
#[derive(Debug)]
pub struct Killed;
impl std::fmt::Display for Killed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("killed")
    }
}
impl wasmi::errors::HostError for Killed {}

// ───────────── the linker ─────────────

const M: &str = "wasi_snapshot_preview1";

/// Register every preview-1 import on `l`.
pub fn add_to_linker(l: &mut Linker<Proc>) -> Result<(), Error> {
    // args / environ
    l.func_wrap(M, "args_sizes_get", |mut c: Caller<'_, Proc>, argc: u32, size: u32| {
        let (m, p) = split(&mut c)?;
        let n = p.args.len() as u32;
        let s: usize = p.args.iter().map(|a| a.len() + 1).sum();
        done(put32(m, argc, n).and_then(|_| put32(m, size, s as u32)))
    })?;
    l.func_wrap(M, "args_get", |mut c: Caller<'_, Proc>, argv: u32, buf: u32| {
        let (m, p) = split(&mut c)?;
        let items: Vec<String> = p.args.clone();
        done(write_strings(m, &items, argv, buf))
    })?;
    l.func_wrap(M, "environ_sizes_get", |mut c: Caller<'_, Proc>, cnt: u32, size: u32| {
        let (m, p) = split(&mut c)?;
        let s: usize = p.env.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
        done(put32(m, cnt, p.env.len() as u32).and_then(|_| put32(m, size, s as u32)))
    })?;
    l.func_wrap(M, "environ_get", |mut c: Caller<'_, Proc>, envp: u32, buf: u32| {
        let (m, p) = split(&mut c)?;
        let items: Vec<String> = p.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        done(write_strings(m, &items, envp, buf))
    })?;
    // clocks / random / scheduling
    l.func_wrap(M, "clock_res_get", |mut c: Caller<'_, Proc>, id: u32, out: u32| {
        let (m, _) = split(&mut c)?;
        done(if id > 3 { Err(INVAL) } else { put64(m, out, 1_000) })
    })?;
    l.func_wrap(M, "clock_time_get", |mut c: Caller<'_, Proc>, id: u32, _prec: u64, out: u32| {
        let (m, _) = split(&mut c)?;
        let t = match id {
            0 => SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0),
            1..=3 => monotonic_ns(),
            _ => return done(Err(INVAL)),
        };
        done(put64(m, out, t))
    })?;
    l.func_wrap(M, "random_get", |mut c: Caller<'_, Proc>, buf: u32, len: u32| {
        let (m, _) = split(&mut c)?;
        let mut b = vec![0u8; len as usize];
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).is_err() {
            return done(Err(IO));
        }
        done(put(m, buf, &b))
    })?;
    l.func_wrap(M, "sched_yield", |_c: Caller<'_, Proc>| -> Result<i32, Error> {
        std::thread::yield_now();
        Ok(0)
    })?;
    l.func_wrap(M, "proc_exit", |_c: Caller<'_, Proc>, code: u32| -> Result<(), Error> { Err(Error::i32_exit(code as i32)) })?;
    l.func_wrap(M, "proc_raise", |_c: Caller<'_, Proc>, _sig: u32| -> Result<i32, Error> { Ok(NOSYS as i32) })?;
    l.func_wrap(M, "poll_oneoff", poll_oneoff)?;
    // descriptors
    l.func_wrap(M, "fd_write", |mut c: Caller<'_, Proc>, fd: u32, iov: u32, n: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        if killed(p) {
            return Err(Error::host(Killed));
        }
        done(fd_write(m, p, fd, iov, n, out, None))
    })?;
    l.func_wrap(M, "fd_pwrite", |mut c: Caller<'_, Proc>, fd: u32, iov: u32, n: u32, off: u64, out: u32| {
        let (m, p) = split(&mut c)?;
        done(fd_write(m, p, fd, iov, n, out, Some(off)))
    })?;
    l.func_wrap(M, "fd_read", |mut c: Caller<'_, Proc>, fd: u32, iov: u32, n: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        if killed(p) {
            return Err(Error::host(Killed));
        }
        done(fd_read(m, p, fd, iov, n, out, None))
    })?;
    l.func_wrap(M, "fd_pread", |mut c: Caller<'_, Proc>, fd: u32, iov: u32, n: u32, off: u64, out: u32| {
        let (m, p) = split(&mut c)?;
        done(fd_read(m, p, fd, iov, n, out, Some(off)))
    })?;
    l.func_wrap(M, "fd_close", |mut c: Caller<'_, Proc>, fd: u32| {
        let p = c.data_mut();
        done(match p.fds.get_mut(fd as usize) {
            Some(slot @ Some(_)) => {
                *slot = None;
                Ok(())
            }
            _ => Err(BADF),
        })
    })?;
    l.func_wrap(M, "fd_seek", |mut c: Caller<'_, Proc>, fd: u32, off: i64, whence: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let pos = match p.fd(fd)? {
                Fd::File { f, .. } => {
                    let w = match whence {
                        0 => SeekFrom::Start(u64::try_from(off).map_err(|_| INVAL)?),
                        1 => SeekFrom::Current(off),
                        2 => SeekFrom::End(off),
                        _ => return Err(INVAL),
                    };
                    f.seek(w).map_err(|e| from_io(&e))?
                }
                Fd::Dir { .. } => return Err(ISDIR),
                _ => return Err(SPIPE),
            };
            put64(m, out, pos)
        })();
        done(r)
    })?;
    l.func_wrap(M, "fd_tell", |mut c: Caller<'_, Proc>, fd: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            match p.fd(fd)? {
                Fd::File { f, .. } => {
                    let pos = f.stream_position().map_err(|e| from_io(&e))?;
                    put64(m, out, pos)
                }
                _ => Err(SPIPE),
            }
        })();
        done(r)
    })?;
    l.func_wrap(M, "fd_fdstat_get", |mut c: Caller<'_, Proc>, fd: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let (ft, flags) = match p.fd(fd)? {
                Fd::In(_) | Fd::Out(_) => (FT_CHAR, 0u16),
                Fd::File { append, .. } => (FT_FILE, if *append { FDFLAG_APPEND } else { 0 }),
                Fd::Dir { .. } => (FT_DIR, 0),
            };
            let mut b = [0u8; 24];
            b[0] = ft;
            b[2..4].copy_from_slice(&flags.to_le_bytes());
            b[8..16].copy_from_slice(&RIGHTS_ALL.to_le_bytes());
            b[16..24].copy_from_slice(&RIGHTS_ALL.to_le_bytes());
            put(m, out, &b)
        })();
        done(r)
    })?;
    l.func_wrap(M, "fd_fdstat_set_flags", |mut c: Caller<'_, Proc>, fd: u32, flags: u32| {
        let p = c.data_mut();
        done(match p.fd(fd) {
            Ok(Fd::File { append, .. }) => {
                *append = flags as u16 & FDFLAG_APPEND != 0;
                Ok(())
            }
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        })
    })?;
    l.func_wrap(M, "fd_fdstat_set_rights", |_c: Caller<'_, Proc>, _fd: u32, _b: u64, _i: u64| -> Result<i32, Error> { Ok(0) })?;
    l.func_wrap(M, "fd_filestat_get", |mut c: Caller<'_, Proc>, fd: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let st = match p.fd(fd)? {
                Fd::In(_) | Fd::Out(_) => char_filestat(),
                Fd::File { f, .. } => filestat(&f.metadata().map_err(|e| from_io(&e))?),
                Fd::Dir { host, .. } => filestat(&std::fs::metadata(&*host).map_err(|e| from_io(&e))?),
            };
            put(m, out, &st)
        })();
        done(r)
    })?;
    l.func_wrap(M, "fd_filestat_set_size", |mut c: Caller<'_, Proc>, fd: u32, size: u64| {
        let p = c.data_mut();
        done(match p.fd(fd) {
            Ok(Fd::File { f, write: true, .. }) => f.set_len(size).map_err(|e| from_io(&e)),
            Ok(Fd::File { .. }) => Err(BADF),
            Ok(_) => Err(INVAL),
            Err(e) => Err(e),
        })
    })?;
    l.func_wrap(M, "fd_filestat_set_times", |mut c: Caller<'_, Proc>, fd: u32, _a: u64, mt: u64, flags: u32| {
        let p = c.data_mut();
        done(match p.fd(fd) {
            Ok(Fd::File { f, .. }) => set_mtime(f, mt, flags),
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        })
    })?;
    l.func_wrap(M, "fd_sync", |mut c: Caller<'_, Proc>, fd: u32| {
        let p = c.data_mut();
        done(match p.fd(fd) {
            Ok(Fd::File { f, .. }) => f.sync_all().map_err(|e| from_io(&e)),
            Ok(Fd::Out(w)) => w.flush().map_err(|e| from_io(&e)),
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        })
    })?;
    l.func_wrap(M, "fd_datasync", |mut c: Caller<'_, Proc>, fd: u32| {
        let p = c.data_mut();
        done(match p.fd(fd) {
            Ok(Fd::File { f, .. }) => f.sync_data().map_err(|e| from_io(&e)),
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        })
    })?;
    l.func_wrap(M, "fd_advise", |_c: Caller<'_, Proc>, _fd: u32, _o: u64, _l: u64, _a: u32| -> Result<i32, Error> { Ok(0) })?;
    l.func_wrap(M, "fd_allocate", |mut c: Caller<'_, Proc>, fd: u32, off: u64, len: u64| {
        let p = c.data_mut();
        done(match p.fd(fd) {
            Ok(Fd::File { f, write: true, .. }) => {
                let want = off.saturating_add(len);
                match f.metadata() {
                    Ok(md) if md.len() < want => f.set_len(want).map_err(|e| from_io(&e)),
                    Ok(_) => Ok(()),
                    Err(e) => Err(from_io(&e)),
                }
            }
            Ok(_) => Err(BADF),
            Err(e) => Err(e),
        })
    })?;
    l.func_wrap(M, "fd_renumber", |mut c: Caller<'_, Proc>, from: u32, to: u32| {
        let p = c.data_mut();
        let r = (|| -> R<()> {
            let f = p.fds.get_mut(from as usize).and_then(|f| f.take()).ok_or(BADF)?;
            if (to as usize) >= p.fds.len() {
                p.fds.resize_with(to as usize + 1, || None);
            }
            p.fds[to as usize] = Some(f);
            Ok(())
        })();
        done(r)
    })?;
    l.func_wrap(M, "fd_prestat_get", |mut c: Caller<'_, Proc>, fd: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = match p.fds.get(fd as usize).and_then(|f| f.as_ref()) {
            Some(Fd::Dir { guest: Some(g), .. }) => {
                let mut b = [0u8; 8];
                b[4..8].copy_from_slice(&(g.len() as u32).to_le_bytes());
                put(m, out, &b)
            }
            Some(_) => Err(BADF),
            None => Err(BADF),
        };
        done(r)
    })?;
    l.func_wrap(M, "fd_prestat_dir_name", |mut c: Caller<'_, Proc>, fd: u32, buf: u32, len: u32| {
        let (m, p) = split(&mut c)?;
        let r = match p.fds.get(fd as usize).and_then(|f| f.as_ref()) {
            Some(Fd::Dir { guest: Some(g), .. }) => {
                let b = g.as_bytes();
                if (len as usize) < b.len() {
                    Err(NAMETOOLONG)
                } else {
                    put(m, buf, b)
                }
            }
            _ => Err(BADF),
        };
        done(r)
    })?;
    l.func_wrap(M, "fd_readdir", |mut c: Caller<'_, Proc>, fd: u32, buf: u32, len: u32, cookie: u64, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let (host, _) = p.dir(fd)?;
            let bytes = dirents(&host, cookie)?;
            let n = bytes.len().min(len as usize);
            put(m, buf, &bytes[..n])?;
            put32(m, out, n as u32)
        })();
        done(r)
    })?;
    // paths
    l.func_wrap(M, "path_open", path_open)?;
    l.func_wrap(M, "path_filestat_get", |mut c: Caller<'_, Proc>, fd: u32, flags: u32, pp: u32, pl: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let path = path_arg(m, pp, pl)?;
            let follow = flags & LOOKUP_FOLLOW != 0;
            let (host, _) = p.resolve(fd, &path, follow, false)?;
            let md = if follow { std::fs::metadata(&host) } else { std::fs::symlink_metadata(&host) }.map_err(|e| from_io(&e))?;
            put(m, out, &filestat(&md))
        })();
        done(r)
    })?;
    l.func_wrap(M, "path_filestat_set_times", |mut c: Caller<'_, Proc>, fd: u32, _fl: u32, pp: u32, pl: u32, _a: u64, mt: u64, flags: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let path = path_arg(m, pp, pl)?;
            let (host, _) = p.resolve(fd, &path, true, true)?;
            let f = File::options().write(true).open(&host).or_else(|_| File::open(&host)).map_err(|e| from_io(&e))?;
            set_mtime(&f, mt, flags)
        })();
        done(r)
    })?;
    l.func_wrap(M, "path_create_directory", |mut c: Caller<'_, Proc>, fd: u32, pp: u32, pl: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let path = path_arg(m, pp, pl)?;
            let (host, _) = p.resolve(fd, &path, false, true)?;
            std::fs::create_dir(&host).map_err(|e| from_io(&e))
        })();
        done(r)
    })?;
    l.func_wrap(M, "path_remove_directory", |mut c: Caller<'_, Proc>, fd: u32, pp: u32, pl: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let path = path_arg(m, pp, pl)?;
            let (host, root) = p.resolve(fd, &path, false, true)?;
            if host == p.roots[root].host {
                return Err(PERM);
            }
            std::fs::remove_dir(&host).map_err(|e| from_io(&e))
        })();
        done(r)
    })?;
    l.func_wrap(M, "path_unlink_file", |mut c: Caller<'_, Proc>, fd: u32, pp: u32, pl: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let path = path_arg(m, pp, pl)?;
            let (host, _) = p.resolve(fd, &path, false, true)?;
            if std::fs::symlink_metadata(&host).map(|md| md.is_dir()).unwrap_or(false) {
                return Err(ISDIR);
            }
            std::fs::remove_file(&host).map_err(|e| from_io(&e))
        })();
        done(r)
    })?;
    l.func_wrap(M, "path_rename", |mut c: Caller<'_, Proc>, fd: u32, op: u32, ol: u32, nfd: u32, np: u32, nl: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let (from, to) = (path_arg(m, op, ol)?, path_arg(m, np, nl)?);
            let (a, _) = p.resolve(fd, &from, false, true)?;
            let (b, _) = p.resolve(nfd, &to, false, true)?;
            std::fs::rename(&a, &b).map_err(|e| from_io(&e))
        })();
        done(r)
    })?;
    l.func_wrap(M, "path_link", |mut c: Caller<'_, Proc>, fd: u32, _fl: u32, op: u32, ol: u32, nfd: u32, np: u32, nl: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let (from, to) = (path_arg(m, op, ol)?, path_arg(m, np, nl)?);
            let (a, _) = p.resolve(fd, &from, false, true)?;
            let (b, _) = p.resolve(nfd, &to, false, true)?;
            std::fs::hard_link(&a, &b).map_err(|e| from_io(&e))
        })();
        done(r)
    })?;
    // New symlinks are refused: a link is the classic way to point a later open outside the
    // roots, and no tool here needs one.
    l.func_wrap(M, "path_symlink", |_c: Caller<'_, Proc>, _op: u32, _ol: u32, _fd: u32, _np: u32, _nl: u32| -> Result<i32, Error> { Ok(NOTSUP as i32) })?;
    l.func_wrap(M, "path_readlink", |mut c: Caller<'_, Proc>, fd: u32, pp: u32, pl: u32, buf: u32, len: u32, out: u32| {
        let (m, p) = split(&mut c)?;
        let r = (|| -> R<()> {
            let path = path_arg(m, pp, pl)?;
            let (host, _) = p.resolve(fd, &path, false, false)?;
            let t = std::fs::read_link(&host).map_err(|e| from_io(&e))?;
            let s = t.to_string_lossy().into_owned();
            let n = s.len().min(len as usize);
            put(m, buf, &s.as_bytes()[..n])?;
            put32(m, out, n as u32)
        })();
        done(r)
    })?;
    // No sockets in preview 1 without a host-provided one, and none is provided.
    l.func_wrap(M, "sock_accept", |_c: Caller<'_, Proc>, _fd: u32, _f: u32, _o: u32| -> Result<i32, Error> { Ok(NOTSUP as i32) })?;
    l.func_wrap(M, "sock_recv", |_c: Caller<'_, Proc>, _fd: u32, _a: u32, _b: u32, _f: u32, _o: u32, _p: u32| -> Result<i32, Error> { Ok(NOTSUP as i32) })?;
    l.func_wrap(M, "sock_send", |_c: Caller<'_, Proc>, _fd: u32, _a: u32, _b: u32, _f: u32, _o: u32| -> Result<i32, Error> { Ok(NOTSUP as i32) })?;
    l.func_wrap(M, "sock_shutdown", |_c: Caller<'_, Proc>, _fd: u32, _h: u32| -> Result<i32, Error> { Ok(NOTSUP as i32) })?;
    Ok(())
}

fn write_strings(m: &mut [u8], items: &[String], ptrs: u32, buf: u32) -> R<()> {
    let mut at = buf;
    for (i, s) in items.iter().enumerate() {
        put32(m, ptrs + 4 * i as u32, at)?;
        put(m, at, s.as_bytes())?;
        put(m, at + s.len() as u32, &[0])?;
        at += s.len() as u32 + 1;
    }
    Ok(())
}

fn set_mtime(f: &File, mt: u64, flags: u32) -> R<()> {
    // fstflags: ATIM 1, ATIM_NOW 2, MTIM 4, MTIM_NOW 8.
    let when = if flags & 8 != 0 {
        Some(SystemTime::now())
    } else if flags & 4 != 0 {
        Some(UNIX_EPOCH + Duration::from_nanos(mt))
    } else {
        None
    };
    match when {
        Some(t) => f.set_modified(t).map_err(|e| from_io(&e)),
        None => Ok(()),
    }
}

fn fd_write(m: &mut [u8], p: &mut Proc, fd: u32, iov: u32, n: u32, out: u32, at: Option<u64>) -> R<()> {
    let bufs = iovecs(m, iov, n)?;
    let mut data = Vec::new();
    for (ptr, len) in bufs {
        data.extend_from_slice(slice(m, ptr, len)?);
    }
    let written = match p.fd(fd)? {
        Fd::Out(w) => {
            w.write_all(&data).map_err(|e| from_io(&e))?;
            data.len()
        }
        Fd::File { f, write, append, .. } => {
            if !*write {
                return Err(BADF);
            }
            match at {
                Some(off) => {
                    let cur = f.stream_position().map_err(|e| from_io(&e))?;
                    f.seek(SeekFrom::Start(off)).map_err(|e| from_io(&e))?;
                    f.write_all(&data).map_err(|e| from_io(&e))?;
                    f.seek(SeekFrom::Start(cur)).map_err(|e| from_io(&e))?;
                }
                None => {
                    if *append {
                        f.seek(SeekFrom::End(0)).map_err(|e| from_io(&e))?;
                    }
                    f.write_all(&data).map_err(|e| from_io(&e))?;
                }
            }
            data.len()
        }
        Fd::In(_) => return Err(BADF),
        Fd::Dir { .. } => return Err(ISDIR),
    };
    put32(m, out, written as u32)
}

fn fd_read(m: &mut [u8], p: &mut Proc, fd: u32, iov: u32, n: u32, out: u32, at: Option<u64>) -> R<()> {
    let bufs = iovecs(m, iov, n)?;
    let want: usize = bufs.iter().map(|(_, l)| *l as usize).sum();
    let mut data = vec![0u8; want.min(1 << 20)];
    let got = match p.fd(fd)? {
        Fd::In(r) => r.read(&mut data).map_err(|e| from_io(&e))?,
        Fd::File { f, .. } => match at {
            Some(off) => {
                let cur = f.stream_position().map_err(|e| from_io(&e))?;
                f.seek(SeekFrom::Start(off)).map_err(|e| from_io(&e))?;
                let n = f.read(&mut data).map_err(|e| from_io(&e))?;
                f.seek(SeekFrom::Start(cur)).map_err(|e| from_io(&e))?;
                n
            }
            None => f.read(&mut data).map_err(|e| from_io(&e))?,
        },
        Fd::Out(_) => return Err(BADF),
        Fd::Dir { .. } => return Err(ISDIR),
    };
    let mut off = 0usize;
    for (ptr, len) in bufs {
        if off >= got {
            break;
        }
        let take = (len as usize).min(got - off);
        put(m, ptr, &data[off..off + take])?;
        off += take;
    }
    put32(m, out, got as u32)
}

/// Serialised `dirent`s from `cookie` on: `.`, `..`, then the entries sorted by name.
fn dirents(host: &Path, cookie: u64) -> R<Vec<u8>> {
    let mut names: Vec<(String, u8, u64)> = vec![(".".into(), FT_DIR, 0), ("..".into(), FT_DIR, 0)];
    let mut rest: Vec<(String, u8, u64)> = std::fs::read_dir(host)
        .map_err(|e| from_io(&e))?
        .flatten()
        .map(|e| {
            let md = e.metadata().ok();
            #[cfg(unix)]
            let ino = {
                use std::os::unix::fs::DirEntryExt;
                e.ino()
            };
            #[cfg(not(unix))]
            let ino = 0u64;
            (e.file_name().to_string_lossy().into_owned(), e.file_type().map(ftype).unwrap_or_else(|_| md.map(|m| ftype(m.file_type())).unwrap_or(FT_UNKNOWN)), ino)
        })
        .collect();
    rest.sort();
    names.extend(rest);
    let mut out = Vec::new();
    for (i, (name, ft, ino)) in names.iter().enumerate().skip(cookie as usize) {
        out.extend_from_slice(&(i as u64 + 1).to_le_bytes());
        out.extend_from_slice(&ino.to_le_bytes());
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.push(*ft);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(name.as_bytes());
        if out.len() > 1 << 20 {
            break;
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn path_open(mut c: Caller<'_, Proc>, fd: u32, dirflags: u32, pp: u32, pl: u32, oflags: u32, rights: u64, _inherit: u64, fdflags: u32, out: u32) -> Result<i32, Error> {
    let (m, p) = split(&mut c)?;
    let r = (|| -> R<()> {
        let path = path_arg(m, pp, pl)?;
        let (o, ff) = (oflags as u16, fdflags as u16);
        let write = rights & RIGHT_FD_WRITE != 0 || o & (O_CREAT | O_TRUNC) != 0 || ff & FDFLAG_APPEND != 0;
        let read = rights & RIGHT_FD_READ != 0 || !write;
        let (host, root) = p.resolve(fd, &path, dirflags & LOOKUP_FOLLOW != 0, write)?;
        let md = std::fs::metadata(&host).ok();
        if md.as_ref().is_some_and(|m| m.is_dir()) || o & O_DIRECTORY != 0 {
            let md = md.ok_or(NOENT)?;
            if !md.is_dir() {
                return Err(NOTDIR);
            }
            if write {
                return Err(ISDIR);
            }
            let n = p.insert(Fd::Dir { host, root, guest: None });
            return put32(m, out, n);
        }
        let mut oo = OpenOptions::new();
        oo.read(read).write(write && ff & FDFLAG_APPEND == 0).append(ff & FDFLAG_APPEND != 0);
        if o & O_CREAT != 0 && o & O_EXCL != 0 {
            oo.create_new(true);
        } else if o & O_CREAT != 0 {
            oo.create(true);
        }
        if o & O_TRUNC != 0 {
            oo.truncate(true);
        }
        let f = oo.open(&host).map_err(|e| from_io(&e))?;
        let n = p.insert(Fd::File { f, write, append: ff & FDFLAG_APPEND != 0 });
        put32(m, out, n)
    })();
    done(r)
}

/// Clock subscriptions sleep (in short slices, so a kill stops them); descriptor
/// subscriptions are reported ready at once (every stream here is a file or a buffer).
fn poll_oneoff(mut c: Caller<'_, Proc>, subs: u32, events: u32, n: u32, out: u32) -> Result<i32, Error> {
    let kill = c.data().kill.clone();
    let mut evs: Vec<[u8; 32]> = Vec::new();
    let mut sleep_ns: Option<u64> = None;
    {
        let (m, _) = split(&mut c)?;
        let r = (|| -> R<()> {
            for i in 0..n {
                let s = subs + i * 48;
                let userdata = u64_at(m, s)?;
                let tag = slice(m, s + 8, 1)?[0];
                let mut e = [0u8; 32];
                e[0..8].copy_from_slice(&userdata.to_le_bytes());
                e[10] = tag;
                if tag == 0 {
                    let id = u32_at(m, s + 16)?;
                    let timeout = u64_at(m, s + 24)?;
                    let flags = u16::from_le_bytes(slice(m, s + 40, 2)?.try_into().map_err(|_| FAULT)?);
                    let now = if id == 0 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0) } else { monotonic_ns() };
                    let rel = if flags & 1 != 0 { timeout.saturating_sub(now) } else { timeout };
                    sleep_ns = Some(sleep_ns.map_or(rel, |s| s.min(rel)));
                } else {
                    e[16..24].copy_from_slice(&0u64.to_le_bytes());
                }
                evs.push(e);
            }
            Ok(())
        })();
        if let Err(e) = r {
            return Ok(e as i32);
        }
    }
    let fd_ready = evs.iter().any(|e| e[10] != 0);
    if let (Some(ns), false) = (sleep_ns, fd_ready) {
        let until = Instant::now() + Duration::from_nanos(ns);
        while Instant::now() < until {
            if kill.load(Ordering::SeqCst) {
                return Err(Error::host(Killed));
            }
            std::thread::sleep((until - Instant::now()).min(Duration::from_millis(20)));
        }
    }
    // Report the descriptor events, or the clocks when only clocks were asked for.
    let chosen: Vec<[u8; 32]> = if fd_ready { evs.into_iter().filter(|e| e[10] != 0).collect() } else { evs };
    let (m, _) = split(&mut c)?;
    let r = (|| -> R<()> {
        for (i, e) in chosen.iter().enumerate() {
            put(m, events + 32 * i as u32, e)?;
        }
        put32(m, out, chosen.len() as u32)
    })();
    done(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confine_refuses_dotdot_and_symlinks_out_of_the_root() {
        let t = seagent_core::tmp::TempDir::new("seagent-wasi-confine");
        std::fs::create_dir_all(t.path().join("root/sub")).unwrap();
        let root = t.path().join("root").canonicalize().unwrap();
        std::fs::write(t.path().join("secret"), "x").unwrap();
        assert_eq!(confine(&root, &root, "../secret", true), Err(NOTCAPABLE));
        assert_eq!(confine(&root, &root.join("sub"), "../../secret", true), Err(NOTCAPABLE));
        assert_eq!(confine(&root, &root.join("sub"), "../a.txt", true), Ok(root.join("a.txt")));
        assert_eq!(confine(&root, &root, "/etc/passwd", true), Err(NOTCAPABLE));
        assert_eq!(confine(&root, &root, "new/dir/file", true), Ok(root.join("new/dir/file")));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(t.path().join("secret"), root.join("link")).unwrap();
            assert_eq!(confine(&root, &root, "link", true), Err(NOTCAPABLE), "a followed link may not leave");
            assert_eq!(confine(&root, &root, "link", false), Ok(root.join("link")), "the link itself is inside");
            std::os::unix::fs::symlink(t.path(), root.join("dirlink")).unwrap();
            assert_eq!(confine(&root, &root, "dirlink/secret", true), Err(NOTCAPABLE));
            std::os::unix::fs::symlink(t.path().join("nope"), root.join("dangling")).unwrap();
            assert_eq!(confine(&root, &root, "dangling", true), Err(NOTCAPABLE), "a dangling link is not created through");
        }
    }
}
