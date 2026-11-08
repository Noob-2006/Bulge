//! cgroup v1 and v2 for command cleanup and resource caps (ent-024).
//!
//! Process groups (the reaper's unit, `seagent_kernel::reaper`) miss a command that double-forks
//! into a new session; a cgroup does not. When seagent runs in a cgroup subtree it may write to
//! (`Delegate=yes` in its systemd unit, or root), every command gets its own leaf group:
//!
//! * **v2** (unified): `<own>/seagent-exec/<name>`. The "no internal processes" rule means a cgroup
//!   that hands controllers to its children may not hold processes itself, so on first use seagent
//!   moves itself into `<own>/seagent-main` (systemd's documented pattern for delegated services)
//!   and enables `+memory +pids` down to `seagent-exec`. Limits: `memory.max`, `pids.max`; kill:
//!   `cgroup.kill` (5.14+), else SIGKILL to every pid in `cgroup.procs`.
//! * **v1** (RHEL 7/8, Amazon Linux 2): the same leaf under the `memory` and `pids`
//!   hierarchies; limits `memory.limit_in_bytes` and `pids.max`; kill by `cgroup.procs`.
//! * **hybrid**: the v1 controllers (where the limits live).
//!
//! Everything is relative to an injected root (`/` in production), so both layouts are tested
//! against fake `/sys/fs/cgroup` trees. Nothing here is required: no writable subtree means
//! no cgroups, and commands still get their process group.

use crate::hostcaps::{cgroup_version, CgroupVersion};
use std::path::{Path, PathBuf};

/// The writable cgroup subtree seagent manages, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgroups {
    pub version: CgroupVersion,
    /// v2: the `seagent-exec` parent. v1/hybrid: one `seagent-exec` parent per controller hierarchy.
    parents: Vec<PathBuf>,
}

/// One command's leaf group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub version: CgroupVersion,
    /// v2: one directory; v1: one per controller (memory first).
    pub dirs: Vec<PathBuf>,
}

fn own_paths(root: &Path) -> Vec<(String, String)> {
    // `/proc/self/cgroup`: `hierarchy-id:controllers:path`; v2 is `0::/path`.
    std::fs::read_to_string(root.join("proc/self/cgroup")).unwrap_or_default().lines().filter_map(|l| {
        let mut it = l.splitn(3, ':');
        let (_, ctl, path) = (it.next()?, it.next()?, it.next()?);
        Some((ctl.to_string(), path.trim_start_matches('/').to_string()))
    }).collect()
}

#[cfg(unix)]
fn writable(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return false };
    // SAFETY: access(2) on a NUL-terminated path.
    p.is_dir() && unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0
}

/// cgroups are a Linux kernel feature; elsewhere a "cgroup tree" can only be a test fixture.
/// The Windows substitute for the VMM's ceiling is the Job Object in [`crate::host::VmmJob`].
#[cfg(not(unix))]
fn writable(p: &Path) -> bool {
    p.is_dir() && std::fs::metadata(p).is_ok_and(|m| !m.permissions().readonly())
}

fn write(p: &Path, v: &str) -> Result<(), String> {
    std::fs::write(p, v).map_err(|e| format!("{}: {e}", p.display()))
}

impl Cgroups {
    /// The subtree seagent may manage under `root`, or why not.
    pub fn discover(root: &Path) -> Result<Cgroups, String> {
        let version = cgroup_version(root);
        let base = root.join("sys/fs/cgroup");
        let own = own_paths(root);
        match version {
            CgroupVersion::None => Err("no cgroup filesystem mounted".into()),
            CgroupVersion::V2 => {
                let path = own.iter().find(|(c, _)| c.is_empty()).map(|(_, p)| p.clone()).ok_or("no v2 entry in /proc/self/cgroup")?;
                let mine = base.join(&path);
                // Already set up by an earlier call: seagent sits in `<own>/seagent-main`.
                let delegated = if mine.file_name().is_some_and(|n| n == "seagent-main") { mine.parent().map(Path::to_path_buf).unwrap_or(mine) } else { mine };
                if !writable(&delegated) {
                    return Err(format!("{} is not writable (run seagent as a systemd service with Delegate=yes, or as root)", delegated.display()));
                }
                Ok(Cgroups { version, parents: vec![delegated.join("seagent-exec")] })
            }
            CgroupVersion::V1 | CgroupVersion::Hybrid => {
                let mut parents = vec![];
                for ctl in ["memory", "pids"] {
                    let path = own.iter().find(|(c, _)| c.split(',').any(|x| x == ctl)).map(|(_, p)| p.clone()).unwrap_or_default();
                    let dir = base.join(ctl).join(&path);
                    if !writable(&dir) {
                        return Err(format!("{} is not writable (cgroup v1 needs root or a delegated hierarchy)", dir.display()));
                    }
                    parents.push(dir.join("seagent-exec"));
                }
                Ok(Cgroups { version, parents })
            }
        }
    }

    /// Prepare the parent(s): v2 moves seagent itself into `seagent-main` and delegates
    /// `+memory +pids` down to `seagent-exec` (idempotent).
    pub fn prepare(&self) -> Result<(), String> {
        for p in &self.parents {
            std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        if self.version == CgroupVersion::V2 {
            let exec = &self.parents[0];
            let delegated = exec.parent().ok_or("bad cgroup path")?;
            let main = delegated.join("seagent-main");
            if !main.join("cgroup.procs").exists() || !std::fs::read_to_string(main.join("cgroup.procs")).unwrap_or_default().lines().any(|l| l.trim() == std::process::id().to_string()) {
                std::fs::create_dir_all(&main).map_err(|e| format!("{}: {e}", main.display()))?;
                write(&main.join("cgroup.procs"), &std::process::id().to_string())?;
            }
            for dir in [delegated, exec.as_path()] {
                let avail = std::fs::read_to_string(dir.join("cgroup.controllers")).unwrap_or_default();
                let want: Vec<&str> = ["memory", "pids"].into_iter().filter(|c| avail.split_whitespace().any(|a| a == *c)).collect();
                if !want.is_empty() {
                    write(&dir.join("cgroup.subtree_control"), &want.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" "))?;
                }
            }
        }
        Ok(())
    }

    /// A fresh leaf group named `name`.
    pub fn create(&self, name: &str) -> Result<Group, String> {
        let name: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
        let dirs: Vec<PathBuf> = self.parents.iter().map(|p| p.join(&name)).collect();
        for d in &dirs {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        Ok(Group { version: self.version, dirs })
    }
}

impl Group {
    /// Re-open a recorded group (the reaper only has the path).
    pub fn at(dir: &Path) -> Group {
        Group { version: CgroupVersion::V2, dirs: vec![dir.to_path_buf()] }
    }

    /// The path the reaper records.
    pub fn primary(&self) -> &Path {
        &self.dirs[0]
    }

    /// Memory (bytes) and pid caps; 0 leaves a limit unset.
    pub fn limit(&self, memory_bytes: u64, pids: u64) -> Result<(), String> {
        match self.version {
            CgroupVersion::V2 => {
                if memory_bytes > 0 {
                    write(&self.dirs[0].join("memory.max"), &memory_bytes.to_string())?;
                }
                if pids > 0 {
                    write(&self.dirs[0].join("pids.max"), &pids.to_string())?;
                }
            }
            _ => {
                if memory_bytes > 0 {
                    write(&self.dirs[0].join("memory.limit_in_bytes"), &memory_bytes.to_string())?;
                }
                if pids > 0 {
                    if let Some(p) = self.dirs.get(1) {
                        write(&p.join("pids.max"), &pids.to_string())?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Move `pid` (with its threads) into the group, in every hierarchy.
    pub fn add(&self, pid: u32) -> Result<(), String> {
        for d in &self.dirs {
            write(&d.join("cgroup.procs"), &pid.to_string())?;
        }
        Ok(())
    }

    /// Live members.
    pub fn procs(&self) -> Vec<u32> {
        std::fs::read_to_string(self.dirs[0].join("cgroup.procs")).unwrap_or_default().lines().filter_map(|l| l.trim().parse().ok()).collect()
    }

    /// Kill every member: `cgroup.kill` where the kernel has it, else SIGKILL each pid. Never
    /// signals seagent itself or pid 0/1. Returns how many pids were signalled.
    pub fn kill(&self) -> usize {
        let me = std::process::id();
        let kill_file = self.dirs[0].join("cgroup.kill");
        let members: Vec<u32> = self.procs().into_iter().filter(|p| *p > 1 && *p != me).collect();
        if self.version == CgroupVersion::V2 && kill_file.exists() && !members.is_empty() && write(&kill_file, "1").is_ok() {
            return members.len();
        }
        for p in &members {
            #[cfg(unix)]
            // SAFETY: plain kill(2) on a pid read from our own cgroup.
            unsafe {
                libc::kill(*p as i32, libc::SIGKILL)
            };
            #[cfg(not(unix))]
            crate::host::kill_pid(*p, true);
        }
        members.len()
    }

    /// Remove the (empty) group directories.
    pub fn remove(&self) {
        for d in &self.dirs {
            let _ = std::fs::remove_dir(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostcaps::tests_support::seagent_tmp;

    fn w(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn v2_delegated_subtree_gets_leaf_groups_with_limits() {
        let t = seagent_tmp("cg2");
        w(&t, "proc/self/cgroup", "0::/system.slice/seagent.service\n");
        w(&t, "sys/fs/cgroup/cgroup.controllers", "cpu memory pids io");
        w(&t, "sys/fs/cgroup/system.slice/seagent.service/cgroup.controllers", "memory pids");
        let cg = Cgroups::discover(&t).unwrap();
        assert_eq!(cg.version, CgroupVersion::V2);
        cg.prepare().unwrap();
        let svc = t.join("sys/fs/cgroup/system.slice/seagent.service");
        assert_eq!(std::fs::read_to_string(svc.join("seagent-main/cgroup.procs")).unwrap(), std::process::id().to_string(), "seagent leaves the delegated root (no internal processes)");
        assert_eq!(std::fs::read_to_string(svc.join("cgroup.subtree_control")).unwrap(), "+memory +pids");
        let g = cg.create("s-main/42").unwrap();
        assert_eq!(g.primary(), svc.join("seagent-exec/s-main_42"));
        g.limit(256 << 20, 64).unwrap();
        g.add(4242).unwrap();
        assert_eq!(std::fs::read_to_string(g.primary().join("memory.max")).unwrap(), (256u64 << 20).to_string());
        assert_eq!(std::fs::read_to_string(g.primary().join("pids.max")).unwrap(), "64");
        assert_eq!(g.procs(), vec![4242]);
        // `cgroup.kill` present (5.14+): one write kills the whole group.
        w(g.primary(), "cgroup.kill", "0");
        assert_eq!(g.kill(), 1);
        assert_eq!(std::fs::read_to_string(g.primary().join("cgroup.kill")).unwrap(), "1");
    }

    #[test]
    fn v1_hierarchies_rhel_and_al2() {
        let t = seagent_tmp("cg1");
        w(&t, "proc/self/cgroup", "11:pids:/system.slice/seagent.service\n7:memory:/system.slice/seagent.service\n3:cpu,cpuacct:/\n");
        for c in ["memory", "pids"] {
            std::fs::create_dir_all(t.join(format!("sys/fs/cgroup/{c}/system.slice/seagent.service"))).unwrap();
        }
        std::fs::create_dir_all(t.join("sys/fs/cgroup/cpu,cpuacct")).unwrap();
        let cg = Cgroups::discover(&t).unwrap();
        assert_eq!(cg.version, CgroupVersion::V1);
        cg.prepare().unwrap();
        let g = cg.create("job-1").unwrap();
        assert_eq!(g.dirs, vec![t.join("sys/fs/cgroup/memory/system.slice/seagent.service/seagent-exec/job-1"), t.join("sys/fs/cgroup/pids/system.slice/seagent.service/seagent-exec/job-1")]);
        g.limit(1 << 30, 128).unwrap();
        assert_eq!(std::fs::read_to_string(g.dirs[0].join("memory.limit_in_bytes")).unwrap(), (1u64 << 30).to_string());
        assert_eq!(std::fs::read_to_string(g.dirs[1].join("pids.max")).unwrap(), "128");
        g.add(77).unwrap();
        assert_eq!(std::fs::read_to_string(g.dirs[1].join("cgroup.procs")).unwrap(), "77");
        // No members other than ourselves → nothing to kill; never signals seagent.
        w(&g.dirs[0], "cgroup.procs", &std::process::id().to_string());
        assert_eq!(g.kill(), 0);
    }

    #[test]
    fn no_cgroups_or_no_write_access_is_a_reason_not_a_failure() {
        let t = seagent_tmp("cg0");
        assert!(Cgroups::discover(&t).unwrap_err().contains("no cgroup"));
        w(&t, "proc/self/cgroup", "0::/user.slice\n");
        w(&t, "sys/fs/cgroup/cgroup.controllers", "memory");
        assert!(Cgroups::discover(&t).is_err(), "the delegated directory does not exist");
    }
}
