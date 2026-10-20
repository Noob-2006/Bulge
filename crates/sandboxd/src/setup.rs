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
/// Home directory for the unprivileged agent user (on the /home tmpfs).
pub const AGENT_HOME: &str = "/home/agent";

fn mount(args: &[&str]) -> io::Result<()> {
    let status = Command::new("/bin/mount").args(args).status()?;
    if status.success() { Ok(()) } else { Err(io::Error::other(format!("mount {args:?} failed: {status}"))) }
}

/// Lock the guest filesystem down and prepare it for an unprivileged agent that
/// runs as `uid`/`gid`: the workspace overlay and the agent home are owned by
/// that id, `/tmp` is the usual sticky world-writable tmpfs, and the rootfs is
/// read-only. Must run as root (it mounts); privileges are dropped afterwards.
pub fn lock_down(uid: u32, gid: u32) -> io::Result<()> {
    network_up()?;
    // /root stays root-only; /home holds the agent's writable home; /tmp is the
    // standard sticky 1777 so non-root tools can use it.
    for dir in ["/root", "/home"] {
        std::fs::create_dir_all(dir)?;
        mount(&["-t", "tmpfs", "-o", "nosuid,nodev,mode=0755", "tmpfs", dir])?;
    }
    std::fs::create_dir_all("/tmp")?;
    mount(&["-t", "tmpfs", "-o", "nosuid,nodev,mode=1777", "tmpfs", "/tmp"])?;
    std::fs::create_dir_all(AGENT_HOME)?;
    chown(AGENT_HOME, uid, gid)?;
    if !is_mountpoint("/run/bulge") {
        std::fs::create_dir_all("/run/bulge")?;
        mount(&["-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run/bulge"])?;
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
    // The agent (non-root) must be able to create files in the overlay; the upper
    // dir is where its writes land. Owning the mountpoint and upper is enough.
    chown(WORKSPACE_UPPER, uid, gid)?;
    chown(WORKSPACE, uid, gid)?;
    // Last: nothing below may write to the rootfs afterwards.
    mount(&["-o", "remount,ro", "/"])?;
    Ok(())
}

/// Drop every privilege: no supplementary groups, real/effective/saved gid then
/// uid set to the unprivileged id, and `no_new_privs` so a setuid binary can
/// never regain root. After this the process (and everything it execs) has no
/// CAP_SYS_ADMIN, so it cannot remount the rootfs or escape the sandbox. Must be
/// the last privileged action.
pub fn drop_privileges(uid: u32, gid: u32) -> io::Result<()> {
    use nix::unistd::{Gid, Uid, setgroups, setresgid, setresuid};
    nix::sys::prctl::set_no_new_privs().map_err(errno)?;
    setgroups(&[Gid::from_raw(gid)]).map_err(errno)?;
    let gid = Gid::from_raw(gid);
    setresgid(gid, gid, gid).map_err(errno)?;
    let uid = Uid::from_raw(uid);
    setresuid(uid, uid, uid).map_err(errno)?;
    // Sanity: we must no longer be able to become root.
    if setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)).is_ok() {
        return Err(io::Error::other("privilege drop failed: still able to setuid(0)"));
    }
    Ok(())
}

fn errno(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

fn chown(path: &str, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if status.success() { Ok(()) } else { Err(io::Error::other(format!("{program} {args:?} failed: {status}"))) }
}

/// Bring up the passt-backed NIC (if the host attached one) and lease an
/// address. /etc/resolv.conf in the image is a symlink into /run/bulge (tmpfs),
/// so the shared rootfs on the host is never written.
fn network_up() -> io::Result<()> {
    run("/sbin/ip", &["link", "set", "lo", "up"])?;
    if !std::path::Path::new("/sys/class/net/eth0").exists() {
        return Ok(());
    }
    std::fs::create_dir_all("/run/bulge")?;
    mount(&["-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run/bulge"])?;
    std::fs::write("/run/bulge/resolv.conf", "")?;
    run("/sbin/ip", &["link", "set", "eth0", "up"])?;
    run("/sbin/udhcpc", &["-i", "eth0", "-n", "-q", "-t", "5", "-S", "-s", "/usr/local/share/bulge/udhcpc.script"])
}

fn is_mountpoint(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|mounts| mounts.lines().any(|line| line.split_whitespace().nth(1) == Some(path)))
        .unwrap_or(false)
}
