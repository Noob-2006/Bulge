//! Where seagent's shared data lives (bundled skills, roles, plugin catalog, optional MCPs,
//! the VM image builder, the sandbox-browser image sources).
//!
//! Nothing here is baked in at compile time (`env!("CARGO_MANIFEST_DIR")` would write the
//! build directory into the binary and make builds unreproducible). The lookup is purely
//! run-time, in this order:
//!
//! 1. `$SEAGENT_SHARE_DIR`
//! 2. `<exe dir>/../share/seagent`, `<exe dir>/../lib/seagent/share` (what `install.sh` does for
//!    `~/.local/bin`, where `../share/seagent` would be seagent's own data dir) and `<exe dir>/share`
//! 3. `/usr/local/share/seagent`, `/usr/share/seagent` (distro packages, the container image)
//! 4. a source checkout the binary runs from (`target/{debug,release}/seagent` and the test
//!    binaries under `target/debug/deps`): the checkout's `share/`.

use std::path::{Path, PathBuf};

/// A directory counts as a share dir when it has the bundled skills.
fn is_share(p: &Path) -> bool {
    p.join("skills").is_dir()
}

/// The checkout (workspace root) an executable at `exe` runs from, if any: the nearest
/// ancestor holding `Cargo.toml`, `crates/` and `share/skills`.
pub fn source_root_of(exe: &Path) -> Option<PathBuf> {
    exe.ancestors().skip(1).find(|d| d.join("Cargo.toml").is_file() && d.join("crates").is_dir() && is_share(&d.join("share"))).map(Path::to_path_buf)
}

/// Pure form of [`share_dir`]: `env` is `$SEAGENT_SHARE_DIR`, `exe` the running binary.
pub fn share_dir_with(env: Option<PathBuf>, exe: Option<&Path>, system: &[&str]) -> Option<PathBuf> {
    if let Some(p) = env.filter(|p| p.is_dir()) {
        return Some(p);
    }
    if let Some(bin) = exe.and_then(Path::parent) {
        for c in [bin.join("../share/seagent"), bin.join("../lib/seagent/share"), bin.join("share")] {
            if is_share(&c) {
                return c.canonicalize().ok();
            }
        }
    }
    for c in system.iter().map(Path::new) {
        if is_share(c) {
            return Some(c.to_path_buf());
        }
    }
    let root = exe.and_then(|e| e.canonicalize().ok().or_else(|| Some(e.to_path_buf()))).and_then(|e| source_root_of(&e))?;
    root.join("share").canonicalize().ok()
}

/// seagent's shared data dir. See the module docs for the search order.
pub fn share_dir() -> Option<PathBuf> {
    share_dir_with(std::env::var_os("SEAGENT_SHARE_DIR").map(PathBuf::from), std::env::current_exe().ok().as_deref(), crate::layout::system::SHARE)
}

/// A file or directory shipped under the share dir (`rel` like `vm/build-image.sh`).
pub fn share_path(rel: &str) -> Option<PathBuf> {
    share_dir().map(|d| d.join(rel)).filter(|p| p.exists())
}

/// The running checkout's root (`.git` present and the binary lives inside it); `None` for
/// installed binaries.
pub fn running_source_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let root = source_root_of(&exe)?.canonicalize().ok()?;
    root.join(".git").exists().then_some(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tmp::TempDir;

    fn tree(root: &Path, dirs: &[&str]) {
        for d in dirs {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
    }

    #[test]
    fn install_layouts_are_found_relative_to_the_executable() {
        let t = TempDir::new("seagent-share");
        let r = t.path();
        tree(r, &["prefix/bin", "prefix/share/seagent/skills"]);
        let exe = r.join("prefix/bin/seagent");
        let got = share_dir_with(None, Some(&exe), &[]).unwrap();
        assert_eq!(got, r.join("prefix/share/seagent").canonicalize().unwrap());
        // `SEAGENT_SHARE_DIR` wins; a missing one is ignored.
        tree(r, &["custom"]);
        assert_eq!(share_dir_with(Some(r.join("custom")), Some(&exe), &[]).unwrap(), r.join("custom"));
        assert_eq!(share_dir_with(Some(r.join("nope")), Some(&exe), &[]).unwrap(), r.join("prefix/share/seagent").canonicalize().unwrap());
    }

    #[test]
    fn system_dirs_and_the_source_tree_are_fallbacks() {
        let t = TempDir::new("seagent-share-sys");
        let r = t.path();
        tree(r, &["usr/share/seagent/skills", "lone/bin", "repo/crates", "repo/share/skills", "repo/target/debug/deps"]);
        std::fs::write(r.join("repo/Cargo.toml"), "").unwrap();
        let sys = r.join("usr/share/seagent");
        let lone = r.join("lone/bin/seagent");
        assert_eq!(share_dir_with(None, Some(&lone), &[sys.to_str().unwrap()]).unwrap(), sys);
        assert!(share_dir_with(None, Some(&lone), &[]).is_none(), "nothing found: no guessing");
        let dev = r.join("repo/target/debug/deps/seagent-abc");
        assert_eq!(share_dir_with(None, Some(&dev), &[]).unwrap(), r.join("repo/share").canonicalize().unwrap());
        assert_eq!(source_root_of(&dev).unwrap(), r.join("repo"));
    }

    #[test]
    fn this_test_binary_finds_the_checkout_share_dir() {
        // The unit tests run from <root>/target/debug/deps, so the run-time lookup must find
        // the source tree without any compile-time path.
        let d = share_dir().expect("share dir from the test binary's location");
        assert!(d.join("skills").is_dir());
    }
}
