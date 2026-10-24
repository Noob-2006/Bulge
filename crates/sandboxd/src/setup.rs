//! Guest filesystem lockdown, run once before the host connects.
//!
//! - `/` (the host-provided rootfs) becomes read-only.
//! - `/tmp`, `/root`, `/home`, `/run/bulge` are fresh tmpfs; long tool output
//!   is saved under `/home/.bulge-spill` (the agent's, mode 700).
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
    step("bring up network", network_up())?;
    // /root stays root-only; /home holds the agent's writable home; /tmp is the
    // standard sticky 1777 so non-root tools can use it.
    for dir in ["/root", "/home"] {
        step(&format!("create {dir}"), std::fs::create_dir_all(dir))?;
        step(&format!("mount tmpfs on {dir}"), mount(&["-t", "tmpfs", "-o", "nosuid,nodev,mode=0755", "tmpfs", dir]))?;
    }
    step("create /tmp", std::fs::create_dir_all("/tmp"))?;
    step("mount tmpfs on /tmp", mount(&["-t", "tmpfs", "-o", "nosuid,nodev,mode=1777", "tmpfs", "/tmp"]))?;
    step("create agent home", std::fs::create_dir_all(AGENT_HOME))?;
    step("chown agent home", chown(AGENT_HOME, uid, gid))?;
    // The egress bridge's unix socket lives here (see bridge::UNIX_PROXY): on the
    // /home tmpfs, so it is visible in workspace slots, which hide /run/bulge.
    step("create egress socket dir", std::fs::create_dir_all(crate::bridge::UNIX_PROXY_DIR))?;
    step("chown egress socket dir", chown(crate::bridge::UNIX_PROXY_DIR, uid, gid))?;
    step(
        "chmod egress socket dir",
        std::fs::set_permissions(crate::bridge::UNIX_PROXY_DIR, std::os::unix::fs::PermissionsExt::from_mode(0o700)),
    )?;
    step("create spill dir", std::fs::create_dir_all(crate::tools::handlers::SPILL_DIR))?;
    step("chown spill dir", chown(crate::tools::handlers::SPILL_DIR, uid, gid))?;
    step(
        "chmod spill dir",
        std::fs::set_permissions(crate::tools::handlers::SPILL_DIR, std::os::unix::fs::PermissionsExt::from_mode(0o700)),
    )?;
    if !is_mountpoint("/run/bulge") {
        step("create /run/bulge", std::fs::create_dir_all("/run/bulge"))?;
        step("mount tmpfs on /run/bulge", mount(&["-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run/bulge"]))?;
    }
    for dir in [WORKSPACE_LOWER, "/run/bulge/rw"] {
        step(&format!("create {dir}"), std::fs::create_dir_all(dir))?;
    }
    step("mount workspace share", mount(&["-t", "virtiofs", "-o", "ro", "workspace", WORKSPACE_LOWER]))?;
    step("mount tmpfs on /run/bulge/rw", mount(&["-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run/bulge/rw"]))?;
    step("create workspace upper", std::fs::create_dir_all(WORKSPACE_UPPER))?;
    step("create workspace work", std::fs::create_dir_all(WORKSPACE_WORK))?;
    step(
        "create /workspace",
        std::fs::create_dir_all(WORKSPACE).or_else(|e| if e.kind() == io::ErrorKind::ReadOnlyFilesystem { Ok(()) } else { Err(e) }),
    )?;
    let options = format!("lowerdir={WORKSPACE_LOWER},upperdir={WORKSPACE_UPPER},workdir={WORKSPACE_WORK}");
    step("mount workspace overlay", mount(&["-t", "overlay", "-o", &options, "overlay", WORKSPACE]))?;
    // The agent (non-root) must be able to create files in the overlay; the upper
    // dir is where its writes land. Owning the mountpoint and upper is enough.
    step("chown workspace upper", chown(WORKSPACE_UPPER, uid, gid))?;
    step("chown /workspace", chown(WORKSPACE, uid, gid))?;
    // Last: nothing below may write to the rootfs afterwards.
    step("remount rootfs read-only", mount(&["-o", "remount,ro", "/"]))?;
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
    // Non-dumpable: other processes of the same uid (the agent's commands) can
    // neither ptrace sandboxd nor open its /proc fds — e.g. the pipes to the
    // privileged slot helper. Credential changes usually imply this; be explicit.
    nix::sys::prctl::set_dumpable(false).map_err(errno)?;
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

/// Name the lock-down step an error came from (boot failures are otherwise opaque).
fn step<T>(what: &str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| io::Error::new(error.kind(), format!("{what}: {error}")))
}

fn is_mountpoint(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|mounts| mounts.lines().any(|line| line.split_whitespace().nth(1) == Some(path)))
        .unwrap_or(false)
}
