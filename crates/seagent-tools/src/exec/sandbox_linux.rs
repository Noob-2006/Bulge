//! The Linux kernel sandboxes of the local backend (Linux and Android: both kernels have
//! namespaces, Landlock and seccomp; Android rarely ships `bwrap`, which is detected at
//! construction): bubblewrap namespaces with the seccomp deny-list, and the Landlock LSM.
//! Moved here unchanged from `local.rs`; the shared mount layout stays in `local`.

use super::local::{bash_command, layout, spawn_command, which, BwrapConfig, LocalBackend, Layout, PreExec};
use super::sandbox::SandboxConfig;
use super::BackendCtx;
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

// ───────────── bubblewrap ─────────────

/// Linux namespaces via bubblewrap: private mount/pid/ipc/uts (and net unless
/// `network = "host"`) namespaces, system dirs read-only, home hidden, all
/// capabilities dropped.
pub struct BwrapBackend {
    cfg: BwrapConfig,
    l: Layout,
}

impl BwrapBackend {
    pub fn new(cfg: &BwrapConfig, sb: &SandboxConfig, ctx: &BackendCtx) -> Result<BwrapBackend, String> {
        if which(&cfg.binary).is_none() {
            return Err(format!("exec backend bwrap: `{}` not found (install bubblewrap, or use landlock / docker)", cfg.binary));
        }
        let l = layout(sb, ctx)?;
        if !l.network {
            // Fail at construction, not silently at exec time: a sandbox that claims
            // "network disabled" but cannot create its network namespace must refuse to run.
            probe_net_namespace(&cfg.binary)?;
        }
        Ok(BwrapBackend { cfg: cfg.clone(), l })
    }
    pub fn args(&self, req: &ExecRequest) -> Vec<String> {
        let mut a: Vec<String> = ["--die-with-parent", "--unshare-user-try", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try", "--new-session", "--cap-drop", "ALL"].map(String::from).to_vec();
        if req.pty.is_some() || req.detach {
            a.retain(|x| x != "--new-session"); // keep the controlling terminal
        }
        if req.detach {
            a.retain(|x| x != "--die-with-parent");
        }
        if !self.l.network {
            a.push("--unshare-net".into());
        }
        for p in &self.cfg.ro_paths {
            a.extend(["--ro-bind-try".into(), p.clone(), p.clone()]);
        }
        a.extend(["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/home", "--tmpfs", "/root", "--tmpfs", "/run"].map(String::from));
        a.extend(["--bind".into(), self.l.tmp.display().to_string(), "/tmp".into()]);
        let ws = self.l.workspace.display().to_string();
        a.extend([if self.l.writable { "--bind" } else { "--ro-bind" }.into(), ws.clone(), ws.clone()]);
        for (src, dst, ro) in &self.l.binds {
            a.extend([if *ro { "--ro-bind" } else { "--bind" }.into(), src.display().to_string(), dst.clone()]);
        }
        let cwd = req.cwd.as_ref().map(|c| c.display().to_string()).filter(|c| Path::new(c).starts_with(&self.l.workspace)).unwrap_or(ws);
        // The host's TMPDIR usually lives under the hidden /home: point it at the private /tmp.
        a.extend(["--chdir".into(), cwd, "--setenv".into(), "HOME".into(), "/tmp".into(), "--setenv".into(), "TMPDIR".into(), "/tmp".into()]);
        a.extend(self.cfg.extra_args.iter().cloned());
        a.extend(["bash".into(), if req.login { "-lc" } else { "-c" }.into(), req.script.clone()]);
        a
    }
}

impl ExecBackend for BwrapBackend {
    fn id(&self) -> &str {
        "bwrap"
    }
    fn describe(&self) -> String {
        format!(
            "bwrap: Linux namespace sandbox; workspace {} {}, network {}, home hidden, /tmp private, all capabilities dropped, seccomp {}",
            self.l.workspace.display(),
            if self.l.writable { "read-write" } else { "read-only" },
            if self.l.network { "shared with host" } else { "disabled" },
            if self.cfg.seccomp && super::seccomp::program().is_some() { "deny-list on" } else { "off" }
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mut cmd = Command::new(&self.cfg.binary);
        let mut args = self.args(req);
        // ent-023: the seccomp deny-list travels as a pipe fd; only the child sees it (the
        // pre-exec hook clears close-on-exec there), and the parent's copy closes on return.
        let filter = if self.cfg.seccomp { super::seccomp::pipe_with_program()? } else { None };
        let mut hook: Option<PreExec> = None;
        if let Some(fd) = &filter {
            use std::os::fd::AsRawFd;
            let raw = fd.as_raw_fd();
            let at = args.len().saturating_sub(3); // before `bash -c <script>`
            args.splice(at..at, ["--seccomp".to_string(), raw.to_string()]);
            hook = Some(Box::new(move || {
                // SAFETY: fcntl on an fd this process owns, in the forked child before exec.
                if unsafe { libc::fcntl(raw, libc::F_SETFD, 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }));
        }
        cmd.args(args);
        let mut req = req.clone();
        req.cwd = None;
        let child = spawn_command(cmd, &req, hook);
        drop(filter);
        child
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
}

/// Can `bwrap` actually create a network namespace here? `--unshare-net` is not a
/// `-try` flag: this probe runs the same flag the sandbox will use, so a host with
/// user namespaces / netns disabled is refused up front instead of handing the
/// command the host network after a silent partial failure.
pub fn probe_net_namespace(bin: &str) -> Result<(), String> {
    let script = format!("exec {} --unshare-net --unshare-user-try --die-with-parent --ro-bind / / true", super::sh_quote(bin));
    let (st, out) = super::run_capture(&LocalBackend, &script, None, Duration::from_secs(15)).map_err(|e| format!("exec backend bwrap: cannot probe `--unshare-net`: {e}"))?;
    if st.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&out);
    let detail = detail.trim();
    Err(format!(
        "exec backend bwrap: `--unshare-net` failed ({}) — this host cannot create a network namespace (unprivileged user namespaces or netns are disabled); set exec.sandbox.network = \"host\" to accept the host network, or use the landlock / docker backend",
        if detail.is_empty() { "bwrap exited nonzero with no message" } else { detail }
    ))
}

// ───────────── Landlock ─────────────

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const FS_EXECUTE: u64 = 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_WRITE_FILE: u64 = 1 << 1;
const NET_BIND_TCP: u64 = 1;
const NET_CONNECT_TCP: u64 = 2;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// Highest Landlock ABI the kernel supports (0 = unavailable).
pub fn landlock_abi() -> i64 {
    // SAFETY: version query with NULL attr is the documented probe.
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<RulesetAttr>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION) }.max(0)
}

fn fs_all(abi: i64) -> u64 {
    // ABI 1: bits 0..=12; 2 adds REFER (13); 3 adds TRUNCATE (14); 5 adds IOCTL_DEV (15).
    let mut m = (1u64 << 13) - 1;
    if abi >= 2 {
        m |= 1 << 13;
    }
    if abi >= 3 {
        m |= 1 << 14;
    }
    if abi >= 5 {
        m |= 1 << 15;
    }
    m
}

/// Landlock LSM: the command may read system dirs and the workspace, write
/// only the workspace (unless read-only) and its private /tmp; TCP blocked
/// when `network = "none"` (ABI ≥ 4). No namespaces, so it works where user
/// namespaces are disabled. Home and other users' data are unreadable.
pub struct LandlockBackend {
    l: Layout,
    abi: i64,
    ro_paths: Vec<String>,
}

impl LandlockBackend {
    pub fn new(sb: &SandboxConfig, ctx: &BackendCtx) -> Result<LandlockBackend, String> {
        let abi = landlock_abi();
        if abi < 1 {
            return Err("exec backend landlock: the kernel has no Landlock support (CONFIG_SECURITY_LANDLOCK, lsm=landlock); use bwrap or docker".into());
        }
        let l = layout(sb, ctx)?;
        if !l.network && abi < 4 {
            return Err(format!("exec backend landlock: kernel Landlock ABI {abi} cannot restrict networking (needs 4); set exec.sandbox.network = \"host\" or use bwrap"));
        }
        let mut ro_paths = BwrapConfig::default().ro_paths;
        ro_paths.extend(["/dev", "/proc", "/sys"].map(String::from));
        if cfg!(target_os = "android") {
            // Android's system image: the shell, toybox and the runtime live here.
            ro_paths.extend(["/system", "/system_ext", "/vendor", "/apex", "/product", "/odm"].map(String::from));
        }
        Ok(LandlockBackend { l, abi, ro_paths })
    }

    /// Pre-exec hook applying the ruleset in the child.
    fn hook(&self) -> io::Result<PreExec> {
        let abi = self.abi;
        let all = fs_all(abi);
        let read = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
        let mut rules: Vec<(CString, u64)> = Vec::new();
        let c = |p: &Path| CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path with NUL"));
        for p in &self.ro_paths {
            if Path::new(p).exists() {
                rules.push((c(Path::new(p))?, read));
            }
        }
        rules.push((c(Path::new("/dev/null"))?, read | FS_WRITE_FILE));
        rules.push((c(Path::new("/dev/tty"))?, read | FS_WRITE_FILE));
        rules.push((c(Path::new("/dev/pts"))?, read | FS_WRITE_FILE));
        rules.push((c(&self.l.tmp)?, all));
        rules.push((c(&self.l.workspace)?, if self.l.writable { all } else { read }));
        for (src, _, ro) in &self.l.binds {
            rules.push((c(src)?, if *ro { read } else { all }));
        }
        let net = if self.l.network { 0 } else { NET_BIND_TCP | NET_CONNECT_TCP };
        Ok(Box::new(move || {
            // Only async-signal-safe syscalls below.
            let attr = RulesetAttr { handled_access_fs: all, handled_access_net: net };
            let size = if abi >= 4 { std::mem::size_of::<RulesetAttr>() } else { 8 };
            // SAFETY: attr outlives the call; size matches the ABI.
            let rs = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size, 0u32) };
            if rs < 0 {
                return Err(io::Error::last_os_error());
            }
            for (path, access) in &rules {
                // SAFETY: valid C string; O_PATH fd closed after use.
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 {
                    continue; // missing optional path
                }
                // Directories get the full mask; files only file rights.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: valid fd and stat buffer.
                let is_dir = unsafe { libc::fstat(fd, &mut st) } == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
                let allowed = if is_dir { *access } else { *access & (FS_EXECUTE | FS_READ_FILE | FS_WRITE_FILE | (1 << 14)) };
                let pb = PathBeneath { allowed_access: allowed & all, parent_fd: fd };
                // SAFETY: rule struct valid for the call.
                unsafe {
                    libc::syscall(libc::SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb as *const PathBeneath, 0u32);
                    libc::close(fd);
                }
            }
            // SAFETY: plain prctl/syscall.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::syscall(libc::SYS_landlock_restrict_self, rs, 0u32) != 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(rs as i32);
            }
            Ok(())
        }))
    }
}

impl ExecBackend for LandlockBackend {
    fn id(&self) -> &str {
        "landlock"
    }
    fn describe(&self) -> String {
        format!(
            "landlock: Landlock ABI {} file-system sandbox; workspace {} {}, network {}, home unreadable",
            self.abi,
            self.l.workspace.display(),
            if self.l.writable { "read-write" } else { "read-only" },
            if self.l.network { "allowed" } else { "TCP blocked" }
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mut cmd = bash_command(req);
        if req.cwd.as_ref().is_none_or(|c| !c.starts_with(&self.l.workspace)) {
            cmd.current_dir(&self.l.workspace);
        }
        cmd.env("HOME", &self.l.tmp).env("TMPDIR", &self.l.tmp);
        spawn_command(cmd, req, Some(self.hook()?))
    }
    fn temp_dir(&self) -> String {
        self.l.tmp.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{drain, run_capture};
    use crate::testutil::tmpdir;
    use std::sync::Arc;

    fn req(script: &str) -> ExecRequest {
        ExecRequest { script: script.into(), ..Default::default() }
    }

    #[test]
    fn bwrap_hides_home_and_blocks_network() {
        if which("bwrap").is_none() || run_capture(&LocalBackend, "bwrap --unshare-user-try --ro-bind / / true", None, Duration::from_secs(5)).map(|r| !r.0.success()).unwrap_or(true) {
            eprintln!("skipping bwrap_hides_home_and_blocks_network: bwrap is not usable on this host (missing, or user namespaces disabled)");
            return;
        }
        let ws = tmpdir("bwrapws");
        // Trailing newline: `cat` is followed by more commands and the last line is asserted.
        std::fs::write(ws.join("f.txt"), "inside\n").unwrap();
        let home = tmpdir("bwraphome");
        let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
        let ctx = BackendCtx { workspace: ws.clone(), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home: home.clone(), sandboxed: true };
        let b = BwrapBackend::new(&BwrapConfig::default(), &sb, &ctx).unwrap();
        // Capabilities are dropped before the command runs.
        let a = b.args(&req("true"));
        assert!(a.windows(2).any(|w| w[0] == "--cap-drop" && w[1] == "ALL"), "{a:?}");
        assert!(a.iter().any(|x| x == "--unshare-net"), "{a:?}");
        let script = format!(
            "cat {}/f.txt; echo w > {}/new.txt; ls $HOME_REAL 2>&1 | head -1\n\
             echo ROUTE; cat /proc/net/route\n\
             echo IPROUTE; ip route 2>&1\n\
             echo DEV; cat /proc/net/dev\n\
             echo TCP; (exec 3<>/dev/tcp/1.1.1.1/80) 2>/dev/null && echo net-open || echo net-denied",
            ws.display(),
            ws.display()
        );
        let mut r = req(&script);
        r.env.push(("HOME_REAL".into(), std::env::var("HOME").unwrap_or_default()));
        r.cwd = Some(ws.clone());
        let (st, out) = drain(b.spawn(&r).unwrap(), Duration::from_secs(15)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(st.success() && s.contains("inside"), "{s}");
        assert!(ws.join("new.txt").exists(), "rw workspace");
        let section = |name: &str| -> String {
            let start = match s.find(&format!("\n{name}\n")) {
                Some(i) => i + name.len() + 2,
                None => return String::new(),
            };
            s[start..].split('\n').take_while(|l| !["ROUTE", "IPROUTE", "DEV", "TCP"].contains(l)).collect::<Vec<_>>().join("\n")
        };
        // No routes at all: /proc/net/route has only its header line.
        let route = section("ROUTE");
        let lines: Vec<&str> = route.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "only the /proc/net/route header, got {route:?}");
        assert!(lines[0].starts_with("Iface"), "{route:?}");
        // `ip route` prints nothing, and only loopback exists.
        assert_eq!(section("IPROUTE").trim(), "", "ip route must be empty in the sandbox");
        let dev = section("DEV");
        assert!(dev.contains("lo:") && !dev.contains("eth0") && !dev.contains("enp") && !dev.contains("wlan"), "only loopback: {dev:?}");
        // Opening a TCP connection to the outside fails.
        assert!(section("TCP").contains("net-denied"), "{s}");
        // ro
        let sb = SandboxConfig { workspace_access: "ro".into(), ..Default::default() };
        let b = BwrapBackend::new(&BwrapConfig::default(), &sb, &ctx).unwrap();
        let (st, _) = drain(b.spawn(&req(&format!("echo x > {}/ro.txt", ws.display()))).unwrap(), Duration::from_secs(10)).unwrap();
        assert!(!st.success() && !ws.join("ro.txt").exists());
        // none: real workspace invisible, scratch dir used.
        let sb = SandboxConfig::default();
        let b = BwrapBackend::new(&BwrapConfig::default(), &sb, &ctx).unwrap();
        let (_, out) = drain(b.spawn(&req(&format!("cat {}/f.txt 2>&1; pwd", ws.display()))).unwrap(), Duration::from_secs(10)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("inside") && s.contains("sandboxes/t/workspace"), "{s}");
        assert!(b.describe().contains("network disabled"));
        // ent-023: the seccomp deny-list is on — a new user namespace or a keyring call from
        // inside is refused, ordinary commands still run.
        assert!(b.describe().contains("seccomp deny-list on"), "{}", b.describe());
        if which("unshare").is_some() {
            let (_, out) = drain(b.spawn(&req("unshare -U true 2>/dev/null; echo rc=$?; echo fine")).unwrap(), Duration::from_secs(10)).unwrap();
            let s = String::from_utf8_lossy(&out);
            assert!(s.contains("fine") && !s.contains("rc=0"), "unshare must be refused: {s}");
        }
        let off = BwrapConfig { seccomp: false, ..BwrapConfig::default() };
        assert!(BwrapBackend::new(&off, &sb, &ctx).unwrap().describe().contains("seccomp off"));
    }

    #[test]
    fn bwrap_network_probe_reports_an_unusable_netns() {
        // A bwrap binary that always fails stands in for a host without netns:
        // construction must refuse with a message naming `--unshare-net`.
        let d = tmpdir("bwrapfake");
        let bin = d.join("bwrap");
        std::fs::write(&bin, "#!/bin/sh\necho 'bwrap: Failed to unshare network namespace: Operation not permitted' >&2\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = BwrapConfig { binary: bin.display().to_string(), ..Default::default() };
        let e = probe_net_namespace(&cfg.binary).unwrap_err();
        assert!(e.contains("--unshare-net") && e.contains("exec.sandbox.network"), "{e}");
        let ctx = BackendCtx { workspace: d.clone(), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home: d.clone(), sandboxed: true };
        let err = BwrapBackend::new(&cfg, &SandboxConfig::default(), &ctx).err().expect("network-none bwrap must refuse to build");
        assert!(err.contains("--unshare-net"), "{err}");
        // network = "host" is the documented way out; no probe is attempted.
        let host = SandboxConfig { network: "host".into(), ..Default::default() };
        assert!(BwrapBackend::new(&cfg, &host, &ctx).is_ok());
    }

    #[test]
    fn landlock_restricts_writes_and_home() {
        if landlock_abi() < 4 {
            eprintln!("skipping: landlock ABI {}", landlock_abi());
            return;
        }
        let ws = tmpdir("llws");
        let home = tmpdir("llhome");
        let outside = tmpdir("lloutside");
        let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
        let ctx = BackendCtx { workspace: ws.clone(), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home, sandboxed: true };
        let b = LandlockBackend::new(&sb, &ctx).unwrap();
        let script = format!("echo ok > {ws}/in.txt && echo in-ok; echo bad > {out}/x.txt 2>/dev/null || echo out-denied; cat {out}/../ 2>/dev/null; (exec 3<>/dev/tcp/127.0.0.1/9 && echo net-open) 2>/dev/null || echo net-denied", ws = ws.display(), out = outside.display());
        let (_, out) = drain(b.spawn(&req(&script)).unwrap(), Duration::from_secs(10)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("in-ok") && s.contains("out-denied") && s.contains("net-denied"), "{s}");
        assert!(!outside.join("x.txt").exists());
    }
}
