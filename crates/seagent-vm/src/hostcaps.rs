//! What the host kernel can do for a namespace sandbox (ent-023/024/026): kernel release,
//! Landlock ABI, unprivileged user namespaces, seccomp and the cgroup layout.
//!
//! Every probe reads files under a root directory ([`HostKernel::detect_in`]), so the
//! degradation table in [`crate::policy`] is tested against fake `/proc` and `/sys` trees for
//! RHEL 7/8, Amazon Linux 2 and a current kernel — never against the machine running the tests.
//! [`HostKernel::detect`] is the production entry: the same reads on `/`, with the Landlock ABI
//! taken from the real `landlock_create_ruleset` version probe when the kernel answers it.

use serde::Serialize;
use std::path::Path;

/// cgroup layout of the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CgroupVersion {
    /// No cgroup filesystem mounted (a bare chroot, some containers).
    None,
    /// Legacy per-controller hierarchies only (RHEL 7/8, Amazon Linux 2 defaults).
    V1,
    /// v1 controllers plus the unified hierarchy at `/sys/fs/cgroup/unified` (systemd hybrid).
    Hybrid,
    /// Unified hierarchy (`cgroup.controllers` at the mount root).
    #[default]
    V2,
}

impl CgroupVersion {
    pub fn label(self) -> &'static str {
        match self {
            CgroupVersion::None => "none",
            CgroupVersion::V1 => "v1",
            CgroupVersion::Hybrid => "hybrid (v1 controllers + v2)",
            CgroupVersion::V2 => "v2",
        }
    }
}

/// The host kernel's sandbox-relevant features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostKernel {
    /// `uname -r` (from `/proc/sys/kernel/osrelease`).
    pub release: String,
    /// `(major, minor)` parsed from `release`.
    pub version: (u32, u32),
    /// Highest Landlock ABI (0 = no Landlock: kernel < 5.13, or not in the active LSM list).
    pub landlock_abi: u32,
    /// Unprivileged user namespaces can be created (bwrap, rootless podman need them).
    pub userns: bool,
    /// Why user namespaces are off, when they are (the sysctl that says so).
    pub userns_blocker: Option<String>,
    /// seccomp filter mode is available.
    pub seccomp: bool,
    pub cgroup: CgroupVersion,
}

impl Default for HostKernel {
    /// A current kernel with everything on (what the decision table assumes when a caller
    /// builds [`crate::Capabilities`] by hand).
    fn default() -> Self {
        HostKernel { release: "6.8.0".into(), version: (6, 8), landlock_abi: 4, userns: true, userns_blocker: None, seccomp: true, cgroup: CgroupVersion::V2 }
    }
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel.trim_start_matches('/'))).ok().map(|s| s.trim().to_string())
}

/// `(major, minor)` of a release string (`4.18.0-553.el8_10.x86_64` → `(4, 18)`).
pub fn parse_version(release: &str) -> (u32, u32) {
    let mut it = release.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// The Landlock ABI a kernel of this version ships (5.13 → 1, 5.19 → 2, 6.2 → 3, 6.7 → 4,
/// 6.10 → 5, 6.12 → 6). Used when the real probe is unavailable (fake roots, tests).
pub fn landlock_abi_for(version: (u32, u32)) -> u32 {
    const TABLE: &[((u32, u32), u32)] = &[((6, 12), 6), ((6, 10), 5), ((6, 7), 4), ((6, 2), 3), ((5, 19), 2), ((5, 13), 1)];
    TABLE.iter().find(|(v, _)| version >= *v).map(|(_, abi)| *abi).unwrap_or(0)
}

/// The real ABI from the kernel (`landlock_create_ruleset(NULL, 0, VERSION)`); 0 when absent.
pub fn landlock_abi_probe() -> u32 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the documented version query: NULL attr, size 0, flag LANDLOCK_CREATE_RULESET_VERSION.
        let r = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32) };
        r.max(0) as u32
    }
    #[cfg(not(target_os = "linux"))]
    0
}

impl HostKernel {
    /// Detect from the files under `root` (`/` in production, a fake tree in tests).
    pub fn detect_in(root: &Path) -> HostKernel {
        let release = read(root, "proc/sys/kernel/osrelease").unwrap_or_default();
        let version = parse_version(&release);
        let lsm = read(root, "sys/kernel/security/lsm").unwrap_or_default();
        let lsm_landlock = lsm.split(',').any(|m| m.trim() == "landlock");
        let landlock_abi = if lsm_landlock { landlock_abi_for(version) } else { 0 };
        let max_ns = read(root, "proc/sys/user/max_user_namespaces").and_then(|s| s.parse::<u64>().ok());
        let clone = read(root, "proc/sys/kernel/unprivileged_userns_clone");
        let userns_blocker = if max_ns == Some(0) {
            Some("user.max_user_namespaces = 0".to_string())
        } else if clone.as_deref() == Some("0") {
            Some("kernel.unprivileged_userns_clone = 0".to_string())
        } else if version < (3, 8) && version != (0, 0) {
            Some(format!("kernel {release} predates user namespaces"))
        } else {
            None
        };
        let seccomp = root.join("proc/sys/kernel/seccomp/actions_avail").exists() || read(root, "proc/self/status").is_some_and(|s| s.lines().any(|l| l.starts_with("Seccomp:")));
        HostKernel { release, version, landlock_abi, userns: userns_blocker.is_none(), userns_blocker, seccomp, cgroup: cgroup_version(root) }
    }

    /// The running machine. The Landlock ABI comes from the kernel itself when it answers.
    pub fn detect() -> HostKernel {
        let mut h = HostKernel::detect_in(Path::new("/"));
        let real = landlock_abi_probe();
        if real > 0 || h.version >= (5, 13) {
            h.landlock_abi = real;
        }
        h
    }

    /// Lines for `seagent sandbox explain` / `seagent doctor`.
    pub fn report(&self) -> Vec<String> {
        vec![
            format!("kernel: {}", if self.release.is_empty() { "unknown" } else { &self.release }),
            format!(
                "landlock: {}",
                match self.landlock_abi {
                    0 if self.version < (5, 13) => format!("unavailable (kernel {}.{} < 5.13)", self.version.0, self.version.1),
                    0 => "unavailable (not in the active LSM list: boot with lsm=…,landlock)".to_string(),
                    n if n < 4 => format!("ABI {n} (files only; network rules need ABI 4 / kernel 6.7)"),
                    n => format!("ABI {n}"),
                }
            ),
            format!("user namespaces: {}", match &self.userns_blocker { None => "available".to_string(), Some(b) => format!("disabled ({b})") }),
            format!("seccomp: {}", if self.seccomp { "available" } else { "unavailable" }),
            format!("cgroups: {}", self.cgroup.label()),
        ]
    }
}

/// The cgroup layout under `root`.
pub fn cgroup_version(root: &Path) -> CgroupVersion {
    let base = root.join("sys/fs/cgroup");
    if base.join("cgroup.controllers").exists() {
        CgroupVersion::V2
    } else if base.join("unified/cgroup.controllers").exists() {
        CgroupVersion::Hybrid
    } else if ["memory", "pids", "cpu,cpuacct", "cpu"].iter().any(|c| base.join(c).is_dir()) {
        CgroupVersion::V1
    } else {
        CgroupVersion::None
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! Fake `/proc` + `/sys` trees for the distributions the degradation table targets.
    use std::path::Path;

    pub struct Host<'a> {
        pub release: &'a str,
        pub lsm: &'a str,
        pub max_userns: &'a str,
        pub cgroup: &'a str,
    }

    pub const RHEL7: Host = Host { release: "3.10.0-1160.el7.x86_64", lsm: "", max_userns: "0", cgroup: "v1" };
    pub const RHEL8: Host = Host { release: "4.18.0-553.el8_10.x86_64", lsm: "capability,yama,selinux", max_userns: "0", cgroup: "v1" };
    pub const AL2: Host = Host { release: "4.14.355-275.amzn2.x86_64", lsm: "capability,selinux", max_userns: "15000", cgroup: "v1" };
    pub const UBUNTU20: Host = Host { release: "5.4.0-200-generic", lsm: "lockdown,capability,yama,apparmor", max_userns: "63000", cgroup: "hybrid" };
    pub const MODERN: Host = Host { release: "6.8.0-45-generic", lsm: "lockdown,capability,landlock,yama,apparmor", max_userns: "63000", cgroup: "v2" };

    pub fn build(root: &Path, h: &Host) {
        let w = |rel: &str, body: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        w("proc/sys/kernel/osrelease", &format!("{}\n", h.release));
        w("sys/kernel/security/lsm", h.lsm);
        w("proc/sys/user/max_user_namespaces", h.max_userns);
        w("proc/self/status", "Name:\tseagent\nSeccomp:\t0\n");
        match h.cgroup {
            "v2" => w("sys/fs/cgroup/cgroup.controllers", "cpu memory pids"),
            "hybrid" => {
                w("sys/fs/cgroup/unified/cgroup.controllers", "");
                std::fs::create_dir_all(root.join("sys/fs/cgroup/memory")).unwrap();
            }
            "v1" => {
                for c in ["memory", "pids", "cpu,cpuacct"] {
                    std::fs::create_dir_all(root.join("sys/fs/cgroup").join(c)).unwrap();
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
pub(crate) use tests as tests_support;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn old_and_new_kernels_are_read_from_a_fake_root() {
        let t = seagent_tmp("hostcaps");
        let cases = [(&fake::RHEL7, (3, 10), 0, false, CgroupVersion::V1), (&fake::RHEL8, (4, 18), 0, false, CgroupVersion::V1), (&fake::AL2, (4, 14), 0, true, CgroupVersion::V1), (&fake::UBUNTU20, (5, 4), 0, true, CgroupVersion::Hybrid), (&fake::MODERN, (6, 8), 4, true, CgroupVersion::V2)];
        for (i, (h, ver, abi, userns, cg)) in cases.into_iter().enumerate() {
            let root = t.join(format!("h{i}"));
            fake::build(&root, h);
            let k = HostKernel::detect_in(&root);
            assert_eq!((k.version, k.landlock_abi, k.userns, k.cgroup), (ver, abi, userns, cg), "{}", h.release);
            assert!(k.seccomp);
            let r = k.report().join("\n");
            if ver < (5, 13) {
                assert!(r.contains("< 5.13"), "{r}");
            }
            if !userns {
                assert!(r.contains("user.max_user_namespaces = 0"), "{r}");
            }
        }
        // A 6.x kernel without landlock in the LSM list has none either.
        let root = t.join("nolsm");
        fake::build(&root, &fake::Host { lsm: "capability,apparmor", ..fake::MODERN });
        assert_eq!(HostKernel::detect_in(&root).landlock_abi, 0);
        assert!(HostKernel::detect_in(&root).report().join("\n").contains("lsm=…,landlock"));
    }

    #[test]
    fn version_parsing_and_abi_table() {
        assert_eq!(parse_version("4.18.0-553.el8_10.x86_64"), (4, 18));
        assert_eq!(parse_version("6.12.1"), (6, 12));
        assert_eq!(parse_version(""), (0, 0));
        assert_eq!(landlock_abi_for((5, 12)), 0);
        assert_eq!(landlock_abi_for((5, 13)), 1);
        assert_eq!(landlock_abi_for((6, 6)), 3);
        assert_eq!(landlock_abi_for((6, 7)), 4);
        assert_eq!(landlock_abi_for((7, 0)), 6);
    }

    /// A scratch dir under TMPDIR, removed when dropped (also on panic).
    pub(crate) struct Scratch(pub std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    impl std::ops::Deref for Scratch {
        type Target = std::path::Path;
        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }
    pub(crate) fn seagent_tmp(tag: &str) -> Scratch {
        let base = std::env::var_os("TMPDIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let d = base.join(format!("seagent-vm-{tag}-{}-{}", std::process::id(), crate::snapshot::now()));
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
}
