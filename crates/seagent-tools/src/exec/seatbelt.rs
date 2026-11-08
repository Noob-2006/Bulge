//! macOS stand-in for Landlock (docs/cross-platform.md): commands run under
//! `/usr/bin/sandbox-exec -p <profile>` with a generated Seatbelt (SBPL) profile carrying the
//! same policy as the Landlock backend — system directories readable, the workspace readable
//! (writable unless read-only), a private temp dir writable, the home directory unreadable,
//! network off unless `network = "host"`. File metadata (`stat`) stays visible everywhere,
//! which many tools need; file *contents* outside the allowed roots do not.

use super::local::{bash_command, layout, spawn_command, Layout};
use super::sandbox::SandboxConfig;
use super::BackendCtx;
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// System locations a usable shell needs to read (Homebrew lives under /opt).
const SYSTEM_READ: &[&str] = &["/usr", "/bin", "/sbin", "/System", "/Library", "/opt", "/private/etc", "/etc", "/dev", "/Applications", "/private/var/db/timezone", "/var/db/timezone"];

pub struct SeatbeltBackend {
    l: Layout,
    profile: String,
}

/// An SBPL string literal.
fn sbpl_str(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{s}\"")
}

/// Seatbelt matches resolved paths (`/tmp` is `/private/tmp`): canonicalize when possible.
fn real(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The profile for `l` (pure; tested on every OS).
pub(super) fn profile(l: &Layout) -> String {
    let mut read: Vec<PathBuf> = SYSTEM_READ.iter().map(PathBuf::from).collect();
    let mut write: Vec<PathBuf> = vec![real(&l.tmp)];
    let ws = real(&l.workspace);
    if l.writable {
        write.push(ws.clone());
    }
    read.push(ws);
    for (src, _, ro) in &l.binds {
        if *ro {
            read.push(real(src));
        } else {
            write.push(real(src));
        }
    }
    read.extend(write.iter().cloned());
    let list = |v: &[PathBuf]| v.iter().map(|p| format!("(subpath {})", sbpl_str(p))).collect::<Vec<_>>().join(" ");
    let mut s = String::from("(version 1)\n(deny default)\n");
    s.push_str("(allow process-exec process-fork)\n(allow signal (target same-sandbox))\n(allow process-info* (target same-sandbox))\n");
    s.push_str("(allow sysctl-read)\n(allow user-preference-read)\n(allow ipc-posix-sem)\n(allow pseudo-tty)\n");
    s.push_str("(allow file-read-metadata)\n(allow file-read* (literal \"/\"))\n");
    s.push_str(&format!("(allow file-read* {})\n", list(&read)));
    s.push_str(&format!("(allow file-write* {})\n", list(&write)));
    s.push_str("(allow file-read* file-write* file-ioctl (literal \"/dev/null\") (literal \"/dev/tty\") (literal \"/dev/ptmx\") (regex #\"^/dev/ttys[0-9]+$\"))\n");
    s.push_str("(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\") (global-name \"com.apple.system.notification_center\") (global-name \"com.apple.system.logger\") (global-name \"com.apple.logd\"))\n");
    s.push_str("(allow network* (remote unix-socket))\n");
    if l.network {
        s.push_str("(allow network*)\n(allow system-socket)\n");
        s.push_str("(allow mach-lookup (global-name \"com.apple.dnssd.service\") (global-name \"com.apple.SystemConfiguration.DNSConfiguration\") (global-name \"com.apple.SystemConfiguration.configd\") (global-name \"com.apple.trustd\") (global-name \"com.apple.trustd.agent\"))\n");
    }
    s
}

impl SeatbeltBackend {
    pub fn new(sb: &SandboxConfig, ctx: &BackendCtx) -> Result<SeatbeltBackend, String> {
        if !Path::new(SANDBOX_EXEC).is_file() {
            return Err(format!("exec backend seatbelt: {SANDBOX_EXEC} not found; use docker or vm"));
        }
        // sandbox-exec cannot nest: a seagent that already runs sandboxed must refuse here,
        // not at the first command.
        let ok = Command::new(SANDBOX_EXEC).args(["-p", "(version 1)(allow default)", "/usr/bin/true"]).status().map(|s| s.success()).unwrap_or(false);
        if !ok {
            return Err("exec backend seatbelt: sandbox-exec cannot start a sandbox here (is seagent itself sandboxed?); use docker or vm".into());
        }
        let l = layout(sb, ctx)?;
        let profile = profile(&l);
        Ok(SeatbeltBackend { l, profile })
    }
}

impl ExecBackend for SeatbeltBackend {
    fn id(&self) -> &str {
        "seatbelt"
    }
    fn describe(&self) -> String {
        format!(
            "seatbelt: macOS Seatbelt sandbox (sandbox-exec); workspace {} {}, network {}, home unreadable (metadata visible), /tmp private",
            self.l.workspace.display(),
            if self.l.writable { "read-write" } else { "read-only" },
            if self.l.network { "allowed" } else { "disabled" }
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let inner = bash_command(req);
        let mut cmd = Command::new(SANDBOX_EXEC);
        cmd.arg("-p").arg(&self.profile).arg(inner.get_program()).args(inner.get_args());
        let cwd = req.cwd.clone().filter(|c| c.starts_with(&self.l.workspace)).unwrap_or_else(|| self.l.workspace.clone());
        cmd.current_dir(cwd).env("HOME", &self.l.tmp).env("TMPDIR", &self.l.tmp);
        spawn_command(cmd, req, None)
    }
    fn temp_dir(&self) -> String {
        self.l.tmp.display().to_string()
    }
}
