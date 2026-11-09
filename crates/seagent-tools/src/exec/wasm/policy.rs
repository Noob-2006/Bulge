//! The file-system view of the `wasm` backend: a list of roots (guest path → host directory,
//! read-only or writable), the same read / write-root policy the namespace and OS sandboxes
//! get from `local::layout` — the workspace, the session's private `/tmp`, configured binds.
//! The shell interpreter resolves redirections, `cd`, globs and `test` through it; the WASI
//! layer resolves every path a tool opens through the same table ([`super::wasi::confine`]).

use super::wasi::{confine, errno};
use std::path::{Component, Path, PathBuf};

/// One directory the sandbox can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// Absolute path inside the sandbox (`/tmp`, or the host path for the workspace).
    pub guest: String,
    /// Canonical host directory.
    pub host: PathBuf,
    pub write: bool,
    /// Visible to WASI tools (`false`: only the shell itself uses it, e.g. its snapshot dir).
    pub tools: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub roots: Vec<Root>,
}

/// Lexically normalise an absolute guest path (`/a/./b/../c` → `/a/c`); `..` stops at `/`.
pub fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `rel` against the guest directory `cwd` (absolute paths stay as they are).
pub fn join(cwd: &str, rel: &str) -> String {
    if rel.starts_with('/') {
        normalize(rel)
    } else {
        normalize(&format!("{cwd}/{rel}"))
    }
}

/// Canonicalise the deepest existing ancestor and re-append the rest (macOS `/var` →
/// `/private/var` must not make a not-yet-created file look outside its root).
fn canon_existing(p: &Path) -> PathBuf {
    let mut probe = p.to_path_buf();
    let mut tail = Vec::new();
    loop {
        if let Ok(c) = probe.canonicalize() {
            return tail.iter().rev().fold(c, |acc: PathBuf, t: &std::ffi::OsString| acc.join(t));
        }
        match probe.file_name() {
            Some(n) => tail.push(n.to_os_string()),
            None => return p.to_path_buf(),
        }
        if !probe.pop() {
            return p.to_path_buf();
        }
    }
}

fn under(path: &str, prefix: &str) -> Option<String> {
    if prefix == "/" {
        return Some(path.trim_start_matches('/').to_string());
    }
    if path == prefix {
        return Some(String::new());
    }
    path.strip_prefix(prefix).and_then(|r| r.strip_prefix('/')).map(str::to_string)
}

impl Policy {
    /// Add a root; the host directory must exist (it is canonicalised so prefix checks hold).
    pub fn add(&mut self, guest: &str, host: &Path, write: bool, tools: bool) -> Result<(), String> {
        let host = host.canonicalize().map_err(|e| format!("{}: {e}", host.display()))?;
        let guest = normalize(guest);
        self.roots.retain(|r| r.guest != guest);
        self.roots.push(Root { guest, host, write, tools });
        Ok(())
    }

    /// The root whose guest path is the longest prefix of `guest`.
    fn root_of(&self, guest: &str) -> Option<(usize, String)> {
        self.roots.iter().enumerate().filter_map(|(i, r)| under(guest, &r.guest).map(|rest| (i, rest, r.guest.len()))).max_by_key(|(_, _, n)| *n).map(|(i, rest, _)| (i, rest))
    }

    /// Guest path → confined host path (+ root index). `write` needs a writable root.
    pub fn host(&self, guest: &str, write: bool, follow: bool) -> Result<(PathBuf, usize), u16> {
        let g = normalize(guest);
        let (i, rest) = self.root_of(&g).ok_or(errno::NOTCAPABLE)?;
        let r = &self.roots[i];
        if write && !r.write {
            return Err(errno::ROFS);
        }
        Ok((confine(&r.host, &r.host, if rest.is_empty() { "." } else { &rest }, follow)?, i))
    }

    /// Host path → the guest path a tool sees for it (`None` outside every root).
    pub fn guest_of(&self, host: &Path) -> Option<String> {
        let canon = canon_existing(host);
        self.roots
            .iter()
            .filter_map(|r| canon.strip_prefix(&r.host).ok().map(|rest| (r, rest.to_path_buf())))
            .max_by_key(|(r, _)| r.host.components().count())
            .map(|(r, rest)| {
                let tail: Vec<String> = rest.components().filter_map(|c| if let Component::Normal(n) = c { Some(n.to_string_lossy().into_owned()) } else { None }).collect();
                if tail.is_empty() {
                    r.guest.clone()
                } else {
                    normalize(&format!("{}/{}", r.guest, tail.join("/")))
                }
            })
    }

    /// Just the roots WASI tools get as preopens, in order.
    pub fn tool_roots(&self) -> Vec<Root> {
        self.roots.iter().filter(|r| r.tools).cloned().collect()
    }

    /// Short description for `describe()`.
    pub fn summary(&self) -> String {
        self.roots.iter().filter(|r| r.tools).map(|r| format!("{} ({})", r.guest, if r.write { "rw" } else { "ro" })).collect::<Vec<_>>().join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_paths_map_to_the_longest_root_and_back() {
        let t = seagent_core::tmp::TempDir::new("seagent-wasm-policy");
        let ws = t.path().join("ws");
        let tmp = t.path().join("tmp");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        let mut p = Policy::default();
        let wsc = ws.canonicalize().unwrap();
        p.add(&wsc.to_string_lossy(), &ws, true, true).unwrap();
        p.add("/tmp", &tmp, true, true).unwrap();
        assert_eq!(normalize("/a/./b/../c//"), "/a/c");
        assert_eq!(join("/x/y", "../z"), "/x/z");
        assert_eq!(p.host("/tmp/a.txt", true, true).unwrap().0, tmp.canonicalize().unwrap().join("a.txt"));
        assert_eq!(p.host(&format!("{}/src", wsc.display()), false, true).unwrap().0, wsc.join("src"));
        assert_eq!(p.host("/etc/passwd", false, true), Err(errno::NOTCAPABLE));
        assert_eq!(p.guest_of(&tmp.join("q")), Some("/tmp/q".into()));
        assert_eq!(p.guest_of(&wsc.join("src")), Some(format!("{}/src", wsc.display())));
        let mut ro = Policy::default();
        ro.add("/ws", &ws, false, true).unwrap();
        assert_eq!(ro.host("/ws/new", true, true), Err(errno::ROFS));
    }
}
