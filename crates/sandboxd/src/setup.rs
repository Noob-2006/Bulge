//! Guest filesystem lockdown, run once before the host connects.
//!
//! - `/` (the host-provided rootfs) becomes read-only.
//! - `/tmp`, `/root`, `/home`, `/run/bulge` are fresh tmpfs.
//! - `/workspace` is an overlay: the host share (read-only virtiofs tag
//!   `workspace`) below, a tmpfs upper above. Every change the guest makes
//!   stays in the upper dir until the host approves and applies it.

use std::io;
use std::process::Command;

pub const WORKSPACE: &str = "/workspace";
pub const WORKSPACE_LOWER: &str = "/run/bulge/lower";
pub const WORKSPACE_UPPER: &str = "/run/bulge/rw/upper";
const WORKSPACE_WORK: &str = "/run/bulge/rw/work";

fn mount(args: &[&str]) -> io::Result<()> {
    let status = Command::new("/bin/mount").args(args).status()?;
    if status.success() { Ok(()) } else { Err(io::Error::other(format!("mount {args:?} failed: {status}"))) }
}

pub fn lock_down() -> io::Result<()> {
    for dir in ["/tmp", "/root", "/home", "/run/bulge"] {
        std::fs::create_dir_all(dir)?;
        mount(&["-t", "tmpfs", "-o", "nosuid,nodev,mode=0755", "tmpfs", dir])?;
    }
    for dir in [WORKSPACE_LOWER, "/run/bulge/rw"] {
        std::fs::create_dir_all(dir)?;
    }
    mount(&["-t", "virtiofs", "-o", "ro", "workspace", WORKSPACE_LOWER])?;
    mount(&["-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run/bulge/rw"])?;
    std::fs::create_dir_all(WORKSPACE_UPPER)?;
    std::fs::create_dir_all(WORKSPACE_WORK)?;
    std::fs::create_dir_all(WORKSPACE).or_else(|e| if e.kind() == io::ErrorKind::ReadOnlyFilesystem { Ok(()) } else { Err(e) })?;
    let options = format!("lowerdir={WORKSPACE_LOWER},upperdir={WORKSPACE_UPPER},workdir={WORKSPACE_WORK}");
    mount(&["-t", "overlay", "-o", &options, "overlay", WORKSPACE])?;
    // Last: nothing below may write to the rootfs afterwards.
    mount(&["-o", "remount,ro", "/"])?;
    Ok(())
}
