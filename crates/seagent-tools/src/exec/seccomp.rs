//! A seccomp deny-list for the bwrap sandbox (ent-023: "bwrap + seccomp" is the fallback on
//! kernels without Landlock).
//!
//! bwrap applies a classic-BPF program passed as `--seccomp <fd>` to the sandboxed command
//! after its own setup. The program refuses (`EPERM`) the syscalls that turn a shared-kernel
//! sandbox into a host compromise or a cross-sandbox foothold — kernel keyrings, module and
//! kexec loading, mounts and new namespaces, eBPF, perf, userfaultfd, handle-based opens,
//! `ptrace`/`process_vm_*` — the same family Docker's default profile removes. Everything else
//! is allowed, so ordinary build/test tooling keeps working. A foreign architecture (x32 on
//! x86_64, a 32-bit compat call) is refused outright, so the list cannot be bypassed by
//! switching ABI.

use std::io;

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO_EPERM: u32 = 0x0005_0000 | 1;
const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

/// `kexec_file_load`: the libc crate names it on Linux but not for Android (bionic), where
/// the kernel has the same number (x86_64 320, aarch64 294).
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
const SYS_KEXEC_FILE_LOAD: i64 = libc::SYS_kexec_file_load;
#[cfg(all(target_os = "android", target_arch = "x86_64"))]
const SYS_KEXEC_FILE_LOAD: i64 = 320;
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const SYS_KEXEC_FILE_LOAD: i64 = 294;

/// The refused syscalls on this architecture.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_mut))]
pub fn denied() -> Vec<(&'static str, i64)> {
    let mut v = vec![
        ("keyctl", libc::SYS_keyctl),
        ("add_key", libc::SYS_add_key),
        ("request_key", libc::SYS_request_key),
        ("ptrace", libc::SYS_ptrace),
        ("process_vm_readv", libc::SYS_process_vm_readv),
        ("process_vm_writev", libc::SYS_process_vm_writev),
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("pivot_root", libc::SYS_pivot_root),
        ("unshare", libc::SYS_unshare),
        ("setns", libc::SYS_setns),
        ("kexec_load", libc::SYS_kexec_load),
        ("kexec_file_load", SYS_KEXEC_FILE_LOAD),
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("userfaultfd", libc::SYS_userfaultfd),
        ("open_by_handle_at", libc::SYS_open_by_handle_at),
        ("name_to_handle_at", libc::SYS_name_to_handle_at),
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("reboot", libc::SYS_reboot),
        ("acct", libc::SYS_acct),
        ("quotactl", libc::SYS_quotactl),
        ("lookup_dcookie", libc::SYS_lookup_dcookie),
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([("iopl", libc::SYS_iopl), ("ioperm", libc::SYS_ioperm)]);
    v
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn denied() -> Vec<(&'static str, i64)> {
    vec![]
}

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..2].copy_from_slice(&code.to_ne_bytes());
    b[2] = jt;
    b[3] = jf;
    b[4..8].copy_from_slice(&k.to_ne_bytes());
    b
}

/// The raw `struct sock_filter[]` bwrap reads from `--seccomp`. `None` on an architecture
/// without a table (the sandbox then runs without the filter, and `describe` says so).
pub fn program() -> Option<Vec<u8>> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let deny = denied();
        let n = deny.len();
        let mut p: Vec<[u8; 8]> = vec![
            // A = seccomp_data.arch; anything but the native ABI → EPERM.
            insn(LD_W_ABS, 0, 0, 4),
            insn(JEQ_K, 1, 0, AUDIT_ARCH),
            insn(RET_K, 0, 0, RET_ERRNO_EPERM),
            // A = seccomp_data.nr; the x32 range (bit 30) → EPERM.
            insn(LD_W_ABS, 0, 0, 0),
            insn(JGE_K, (n + 1) as u8, 0, 0x4000_0000),
        ];
        for (i, (_, nr)) in deny.iter().enumerate() {
            // Match → jump over the remaining tests and the ALLOW to the EPERM return.
            p.push(insn(JEQ_K, (n - i) as u8, 0, *nr as u32));
        }
        p.push(insn(RET_K, 0, 0, RET_ALLOW));
        p.push(insn(RET_K, 0, 0, RET_ERRNO_EPERM));
        Some(p.concat())
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    None
}

/// A pipe whose read end holds [`program`] (for `bwrap --seccomp <fd>`). Both ends are
/// close-on-exec; the spawn hook clears the flag on the read end in the child only.
pub fn pipe_with_program() -> io::Result<Option<std::os::fd::OwnedFd>> {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    let Some(prog) = program() else { return Ok(None) };
    let mut fds = [0i32; 2];
    // SAFETY: plain pipe2 into a local array; both fds are owned immediately below.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptors from pipe2, owned exactly once.
    let (r, w) = unsafe { (std::os::fd::OwnedFd::from_raw_fd(fds[0]), std::os::fd::OwnedFd::from_raw_fd(fds[1])) };
    // A few hundred bytes: far below the pipe buffer, so this never blocks.
    std::fs::File::from(w).write_all(&prog)?;
    Ok(Some(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn the_program_is_well_formed() {
        let p = program().unwrap();
        let n = denied().len();
        assert_eq!(p.len(), 8 * (5 + n + 2));
        // Every jump lands inside the program.
        for (i, ins) in p.chunks(8).enumerate() {
            let code = u16::from_ne_bytes([ins[0], ins[1]]);
            if code == JEQ_K || code == JGE_K {
                let (jt, jf) = (ins[2] as usize, ins[3] as usize);
                assert!(i + 1 + jt.max(jf) < p.len() / 8, "jump out of range at {i}");
            }
        }
        // The last two instructions are ALLOW then EPERM.
        let k = |i: usize| u32::from_ne_bytes(p[i * 8 + 4..i * 8 + 8].try_into().unwrap());
        assert_eq!((k(p.len() / 8 - 2), k(p.len() / 8 - 1)), (RET_ALLOW, RET_ERRNO_EPERM));
        assert!(denied().iter().any(|(n, _)| *n == "keyctl") && denied().iter().any(|(n, _)| *n == "unshare"));
    }

    /// The filter really applies under bwrap: `unshare` is refused, ordinary commands run.
    /// Needs bwrap and user namespaces; skipped (passes) where the host has neither.
    #[test]
    fn bwrap_runs_with_the_filter_when_available() {
        let Some(bwrap) = crate::exec::local::which("bwrap") else { return };
        let Ok(Some(fd)) = pipe_with_program() else { return };
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let raw = fd.as_raw_fd();
        let run = |script: &str| {
            let mut c = seagent_core::platform::proc::command(&bwrap);
            c.args(["--unshare-user-try", "--die-with-parent", "--ro-bind", "/", "/", "--seccomp", &raw.to_string(), "sh", "-c", script]);
            // SAFETY: fcntl on an fd this process owns, in the forked child before exec.
            unsafe {
                c.pre_exec(move || {
                    libc::fcntl(raw, libc::F_SETFD, 0);
                    Ok(())
                });
            }
            c.output()
        };
        let Ok(out) = run("echo ok") else { return };
        if !out.status.success() {
            return; // no user namespaces here: nothing to test
        }
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
        let Ok(fd2) = pipe_with_program() else { return };
        drop(fd);
        let raw2 = fd2.as_ref().map(|f| f.as_raw_fd()).unwrap();
        let mut c = seagent_core::platform::proc::command(&bwrap);
        c.args(["--unshare-user-try", "--die-with-parent", "--ro-bind", "/", "/", "--seccomp", &raw2.to_string(), "unshare", "-U", "true"]);
        // SAFETY: as above.
        unsafe {
            c.pre_exec(move || {
                libc::fcntl(raw2, libc::F_SETFD, 0);
                Ok(())
            });
        }
        if crate::exec::local::which("unshare").is_some() {
            let out = c.output().unwrap();
            assert!(!out.status.success(), "unshare must be refused inside the filter");
        }
    }
}
