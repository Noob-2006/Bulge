//! The privileged helper: opens and closes slots (snapshot, overlay mount,
//! control socket, slot server), then drops to the agent user for all reads
//! and writes.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{self, BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use serde_json::{Value, json};
use crate::commands::walk_changes;
use crate::setup::{AGENT_HOME, WORKSPACE, WORKSPACE_LOWER, WORKSPACE_UPPER};
use super::{CTL_DIR, Decision, Entry, HelperReply, HelperRequest, SLOTS_ROOT, SlotError, apply_entry, base_entry_checked, ensure_no_symlink_parents, export_from, is_overlay_whiteout, merge_decision, parse_helper_request, read_entry_opt, run_as, slot_base_entry, validate_rel_path, validate_slot, validate_stage_slots};

/// PATH for slot processes (the environment is cleared before exec).
pub(crate) const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub(crate) struct SlotPaths {
    pub(crate) root: PathBuf,
    pub(crate) snap: PathBuf,
    pub(crate) upper: PathBuf,
    pub(crate) work: PathBuf,
    pub(crate) merged: PathBuf,
    pub(crate) home: PathBuf,
    pub(crate) tmp: PathBuf,
    pub(crate) socket: PathBuf,
}

impl SlotPaths {
    pub(crate) fn new(slot: u8) -> Self {
        let root = Path::new(SLOTS_ROOT).join(slot.to_string());
        Self {
            snap: root.join("snap"),
            upper: root.join("upper"),
            work: root.join("work"),
            merged: root.join("merged"),
            home: root.join("home"),
            tmp: root.join("tmp"),
            socket: Path::new(CTL_DIR).join(format!("slot{slot}.sock")),
            root,
        }
    }

    pub(crate) fn prepare(&self, uid: u32, gid: u32) -> Result<(), SlotError> {
        std::fs::create_dir_all(SLOTS_ROOT).map_err(SlotError::failed)?;
        std::fs::set_permissions(SLOTS_ROOT, std::fs::Permissions::from_mode(0o700)).map_err(SlotError::failed)?;
        for dir in [&self.root, &self.snap, &self.upper, &self.work, &self.merged, &self.home, &self.tmp] {
            std::fs::create_dir_all(dir).map_err(SlotError::failed)?;
        }
        set_mode(&self.root, 0o700)?;
        set_mode(&self.snap, 0o755)?;
        set_mode(&self.upper, 0o700)?;
        set_mode(&self.work, 0o700)?;
        set_mode(&self.merged, 0o755)?;
        set_mode(&self.home, 0o700)?;
        set_mode(&self.tmp, 0o1777)?;
        for dir in [&self.upper, &self.home, &self.tmp] {
            std::os::unix::fs::chown(dir, Some(uid), Some(gid)).map_err(SlotError::failed)?;
        }
        Ok(())
    }
}

pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<(), SlotError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(SlotError::failed)
}

pub(crate) fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), SlotError> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(SlotError::failed)
}

pub(crate) fn cstring(path: &Path) -> Result<CString, SlotError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| SlotError::invalid(format!("path contains NUL: {}", path.display())))
}

pub(crate) struct HelperConfig {
    pub(crate) base_uid: u32,
    pub(crate) base_gid: u32,
    pub(crate) egress_proxy: Option<String>,
}

impl HelperConfig {
    pub(crate) fn from_env() -> Result<Self, SlotError> {
        let base_uid = env_id("BULGE_BASE_UID")?;
        let base_gid = env_id("BULGE_BASE_GID")?;
        Ok(Self {
            base_uid,
            base_gid,
            egress_proxy: std::env::var("BULGE_EGRESS_PROXY").ok().filter(|value| !value.is_empty()),
        })
    }
}

pub(crate) fn env_id(name: &str) -> Result<u32, SlotError> {
    std::env::var(name)
        .map_err(|_| SlotError::failed(format!("{name} is not set")))?
        .parse::<u32>()
        .map_err(|e| SlotError::failed(format!("{name}: {e}")))
}

pub(crate) struct OpenSlot {
    pub(crate) child: Child,
}

pub(crate) struct HelperState {
    pub(crate) config: HelperConfig,
    pub(crate) open: HashMap<u8, OpenSlot>,
}

impl HelperState {
    pub(crate) fn new(config: HelperConfig) -> Self {
        Self {
            config,
            open: HashMap::new(),
        }
    }

    pub(crate) fn handle(&mut self, request: HelperRequest) -> Result<Value, SlotError> {
        let slot = validate_slot(request.slot).map_err(SlotError::invalid)?;
        match request.op.as_str() {
            "open" => self.open(slot),
            "changes" => self.changes(slot),
            "export" => {
                let paths = self.validate_paths(&request.paths)?;
                self.export(slot, &paths)
            }
            "merge" => {
                let paths = self.validate_paths(&request.paths)?;
                self.merge(slot, &paths)
            }
            "stage" => {
                let (slot, from) = validate_stage_slots(request.slot, request.from).map_err(SlotError::invalid)?;
                let paths = self.validate_paths(&request.paths)?;
                self.stage(slot, from, &paths)
            }
            "close" => {
                self.close(slot)?;
                Ok(json!({ "slot": slot, "closed": true }))
            }
            other => Err(SlotError::invalid(format!("unknown slot helper operation: {other}"))),
        }
    }

    pub(crate) fn validate_paths(&self, paths: &[String]) -> Result<Vec<PathBuf>, SlotError> {
        paths.iter().map(|path| validate_rel_path(path).map_err(SlotError::invalid)).collect()
    }

    pub(crate) fn require_open(&self, slot: u8) -> Result<&OpenSlot, SlotError> {
        self.open
            .get(&slot)
            .ok_or_else(|| SlotError::new("SLOT_UNAVAILABLE", format!("slot {slot} is not open")))
    }

    pub(crate) fn open(&mut self, slot: u8) -> Result<Value, SlotError> {
        if self.open.contains_key(&slot) {
            self.close(slot)?;
        }
        let paths = SlotPaths::new(slot);
        // Slots run as the workspace owner so they can edit existing files (the
        // host share is owned by it); isolation comes from the slot's own mount,
        // PID and IPC namespaces, not from a different uid.
        let (uid, gid) = (self.config.base_uid, self.config.base_gid);
        let result = (|| -> Result<Child, SlotError> {
            paths.prepare(uid, gid)?;
            snapshot(&paths)?;
            mount_overlay(&paths)?;
            chown_path(&paths.merged, uid, gid)?;
            let listener = bind_control_socket(&paths, self.config.base_uid, self.config.base_gid)?;
            let child = spawn_server(slot, &paths, &self.config, uid, gid, &listener)?;
            drop(listener);
            Ok(child)
        })();
        match result {
            Ok(child) => {
                self.open.insert(slot, OpenSlot { child });
                Ok(json!({ "slot": slot, "uid": uid }))
            }
            Err(error) => {
                let _ = cleanup_slot(&paths);
                Err(error)
            }
        }
    }

    /// A process inside the slot's namespaces (the server's namespace holder),
    /// used to enter its mount namespace.
    pub(crate) fn namespace_pid(&self, slot: u8) -> Result<i32, SlotError> {
        self.open
            .get(&slot)
            .map(|open| open.child.id() as i32)
            .ok_or_else(|| SlotError::new("SLOT_UNAVAILABLE", format!("slot {slot} is not open")))
    }

    pub(crate) fn stage(&self, slot: u8, from: u8, paths_in: &[PathBuf]) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        self.require_open(from)?;
        // SOURCE: read exactly like merge reads the slot side, inside the source
        // slot's mount namespace as the unprivileged owner, with symlink parents
        // refused.
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(from)?;
        let entries: Vec<(PathBuf, Option<Entry>)> = run_as(Some(ns), self.config.base_uid, self.config.base_gid, move || {
            let root = Path::new(WORKSPACE);
            rels.iter()
                .map(|rel| {
                    ensure_no_symlink_parents(root, rel).map_err(SlotError::failed)?;
                    Ok((rel.clone(), read_entry_opt(Some(&root.join(rel)))?))
                })
                .collect()
        })?;
        // DESTINATION: apply the source versions in the staging slot's namespace.
        // The staging slot was opened from the same main state, so there is no
        // conflict check: the worker's version simply wins.
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(slot)?;
        let (base_uid, base_gid) = (self.config.base_uid, self.config.base_gid);
        run_as(Some(ns), base_uid, base_gid, move || {
            let root = Path::new(WORKSPACE);
            for (rel, entry) in &entries {
                apply_entry(root, rel, entry.as_ref(), base_uid, base_gid).map_err(SlotError::failed)?;
            }
            let staged: Vec<String> = rels.iter().map(|rel| rel.to_string_lossy().into_owned()).collect();
            Ok(json!({ "staged": staged }))
        })
    }

    pub(crate) fn close(&mut self, slot: u8) -> Result<(), SlotError> {
        let paths = SlotPaths::new(slot);
        if let Some(mut open) = self.open.remove(&slot) {
            let pgid = open.child.id() as i32;
            let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pgid), nix::sys::signal::Signal::SIGKILL);
            let _ = open.child.wait();
        }
        cleanup_slot(&paths)
    }

    pub(crate) fn changes(&self, slot: u8) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        let paths = SlotPaths::new(slot);
        let base = |rel: &Path| slot_base_entry(&paths.snap, Path::new(WORKSPACE_LOWER), rel, &is_overlay_whiteout);
        let mut out = walk_changes(&paths.upper, &base).map_err(SlotError::failed)?;
        out.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        Ok(json!({ "changes": out }))
    }

    pub(crate) fn export(&self, slot: u8, paths_in: &[PathBuf]) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        let paths = SlotPaths::new(slot);
        // Which paths existed in the base is decided here (root-only snapshot,
        // static while the slot is open); the slot's own files are read as the
        // slot's uid, so a symlink the agent planted can only reach what the
        // agent itself could read.
        let existed: Vec<bool> = paths_in.iter().map(|rel| base_entry_checked(&paths.snap, rel).exists()).collect();
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(slot)?;
        run_as(Some(ns), self.config.base_uid, self.config.base_gid, move || {
            let lookup: std::collections::HashMap<&Path, bool> = rels.iter().map(PathBuf::as_path).zip(existed.iter().copied()).collect();
            export_from(Path::new(WORKSPACE), &rels, &|rel| lookup.get(rel).copied().unwrap_or(false))
        })
    }

    pub(crate) fn merge(&self, slot: u8, paths_in: &[PathBuf]) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        let paths = SlotPaths::new(slot);
        // BASE: the root-only snapshot over the read-only host share; static while
        // the slot is open, and symlink parents are refused.
        let mut bases = Vec::with_capacity(paths_in.len());
        for rel in paths_in {
            bases.push(read_entry_opt(base_entry_checked(&paths.snap, rel).path())?);
        }
        // SLOT: read inside the slot's own mount namespace as the unprivileged
        // owner (never root), with symlink parents refused.
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(slot)?;
        let slots: Vec<Option<Entry>> = run_as(Some(ns), self.config.base_uid, self.config.base_gid, move || {
            let root = Path::new(WORKSPACE);
            rels.iter()
                .map(|rel| {
                    ensure_no_symlink_parents(root, rel).map_err(SlotError::failed)?;
                    read_entry_opt(Some(&root.join(rel)))
                })
                .collect()
        })?;
        // MAIN: read, decide and apply as the main workspace's owner, so a symlink
        // swapped in by anything else in the guest can never redirect a write
        // beyond what that owner may already touch.
        let rels = paths_in.to_vec();
        let (base_uid, base_gid) = (self.config.base_uid, self.config.base_gid);
        run_as(None, base_uid, base_gid, move || {
            let root = Path::new(WORKSPACE);
            let mut merged = Vec::new();
            let mut conflicts = Vec::new();
            for ((rel, base), slot_entry) in rels.iter().zip(bases.iter()).zip(slots.iter()) {
                let display = rel.to_string_lossy().into_owned();
                if let Err(error) = ensure_no_symlink_parents(root, rel) {
                    conflicts.push(json!({ "path": display, "reason": error.to_string() }));
                    continue;
                }
                let main_entry = read_entry_opt(Some(&root.join(rel)))?;
                match merge_decision(base.as_ref(), slot_entry.as_ref(), main_entry.as_ref()) {
                    Decision::Nothing => {}
                    Decision::Conflict(reason) => conflicts.push(json!({ "path": display, "reason": reason })),
                    Decision::Apply => {
                        apply_entry(root, rel, slot_entry.as_ref(), base_uid, base_gid).map_err(SlotError::failed)?;
                        merged.push(display);
                    }
                }
            }
            Ok(json!({ "merged": merged, "conflicts": conflicts }))
        })
    }
}

pub fn helper_main() -> Result<(), String> {
    helper_run().map_err(|error| error.to_string())
}

pub(crate) fn helper_run() -> Result<(), SlotError> {
    let config = HelperConfig::from_env()?;
    let mut state = HelperState::new(config);
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut line = String::new();
        let read = input.read_line(&mut line).map_err(SlotError::failed)?;
        if read == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let response = match parse_helper_request(line) {
            Ok(request) => {
                let id = request.id;
                match state.handle(request) {
                    Ok(value) => HelperReply::Ok { id, value },
                    Err(error) => HelperReply::Err {
                        id,
                        code: error.code,
                        message: error.message,
                    },
                }
            }
            Err(message) => HelperReply::Err {
                id: 0,
                code: "INVALID_PARAMS".into(),
                message,
            },
        };
        write_helper_reply(&mut output, &response).map_err(SlotError::failed)?;
    }
    let slots: Vec<u8> = state.open.keys().copied().collect();
    for slot in slots {
        let _ = state.close(slot);
    }
    Ok(())
}

pub(crate) fn write_helper_reply(output: &mut impl Write, reply: &HelperReply) -> io::Result<()> {
    match reply {
        HelperReply::Ok { id, value } => serde_json::to_writer(&mut *output, &json!({ "id": id, "ok": value }))?,
        HelperReply::Err { id, code, message } => {
            serde_json::to_writer(&mut *output, &json!({ "id": id, "err": { "code": code, "message": message } }))?
        }
    }
    output.write_all(b"\n")?;
    output.flush()
}

pub(crate) fn snapshot(paths: &SlotPaths) -> Result<(), SlotError> {
    let source = format!("{WORKSPACE_UPPER}/.");
    let output = Command::new("/bin/cp")
        .args(["-a", "--preserve=all", &source])
        .arg(&paths.snap)
        .output()
        .map_err(SlotError::failed)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(SlotError::failed(format!(
            "snapshot failed: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

pub(crate) fn mount_overlay(paths: &SlotPaths) -> Result<(), SlotError> {
    let target = cstring(&paths.merged)?;
    let fstype = CString::new("overlay").expect("static string");
    let source = CString::new("overlay").expect("static string");
    let data = CString::new(format!(
        "lowerdir={}:{},upperdir={},workdir={}",
        paths.snap.display(),
        WORKSPACE_LOWER,
        paths.upper.display(),
        paths.work.display()
    ))
    .map_err(|_| SlotError::failed("overlay path contains NUL"))?;
    nix::mount::mount(
        Some(source.as_c_str()),
        target.as_c_str(),
        Some(fstype.as_c_str()),
        nix::mount::MsFlags::empty(),
        Some(data.as_c_str()),
    )
    .map_err(|e| SlotError::failed(format!("mount overlay {}: {e}", paths.merged.display())))
}

pub(crate) fn bind_control_socket(paths: &SlotPaths, base_uid: u32, base_gid: u32) -> Result<std::os::unix::net::UnixListener, SlotError> {
    std::fs::create_dir_all(CTL_DIR).map_err(SlotError::failed)?;
    chown_path(Path::new(CTL_DIR), base_uid, base_gid)?;
    set_mode(Path::new(CTL_DIR), 0o700)?;
    match std::fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SlotError::failed(error)),
    }
    let listener = std::os::unix::net::UnixListener::bind(&paths.socket).map_err(SlotError::failed)?;
    chown_path(&paths.socket, base_uid, base_gid)?;
    set_mode(&paths.socket, 0o600)?;
    Ok(listener)
}

#[allow(unsafe_code)] // pre_exec namespace/uid setup (see SAFETY below)
pub(crate) fn spawn_server(
    slot: u8,
    paths: &SlotPaths,
    config: &HelperConfig,
    uid: u32,
    gid: u32,
    listener: &std::os::unix::net::UnixListener,
) -> Result<Child, SlotError> {
    use std::os::fd::AsRawFd;

    let listener_fd = listener.as_raw_fd();
    let slot_name = slot.to_string();
    // Prepare everything that needs allocation before entering pre_exec.
    let merged = cstring(&paths.merged)?;
    let workspace = cstring(Path::new(WORKSPACE))?;
    let home = cstring(&paths.home)?;
    let agent_home = cstring(Path::new(AGENT_HOME))?;
    let tmp = cstring(&paths.tmp)?;
    let tmp_target = cstring(Path::new("/tmp"))?;
    let run_bulge = cstring(Path::new("/run/bulge"))?;
    let root = cstring(Path::new("/"))?;
    let tmpfs = CString::new("tmpfs").expect("static string");
    let tmpfs_data = CString::new("mode=0755").expect("static string");

    // Stage 1 (this pre_exec, still root): new mount/PID/IPC namespaces and the
    // slot's view of the filesystem, then exec the holder (stage 2, see
    // `holder_main`), which forks PID 1 of the new PID namespace (stage 3).
    let mut command = Command::new("/proc/self/exe");
    command
        .arg("--slot-holder")
        .arg(&slot_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env_clear()
        .env("HOME", AGENT_HOME)
        .env("PATH", DEFAULT_PATH)
        .env("BULGE_SLOT", &slot_name)
        .env("BULGE_BASE_UID", uid.to_string())
        .env("BULGE_BASE_GID", gid.to_string());
    if let Some(proxy) = &config.egress_proxy {
        command.env("BULGE_EGRESS_PROXY", proxy);
    }
    command.current_dir("/");

    // SAFETY: pre_exec runs after fork and before exec. Every call below is an
    // async-signal-safe syscall wrapper; all CStrings were allocated before the
    // fork. fd 3 is the inherited listening socket (dup2 clears CLOEXEC).
    unsafe {
        command.pre_exec(move || {
            let sys = |result: nix::Result<()>| result.map_err(|error| io::Error::from_raw_os_error(error as i32));
            // Own process group so `close` can kill the holder and the slot at once.
            if nix::libc::setpgid(0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            sys(nix::sched::unshare(
                nix::sched::CloneFlags::CLONE_NEWNS
                    | nix::sched::CloneFlags::CLONE_NEWPID
                    | nix::sched::CloneFlags::CLONE_NEWIPC
                    // Own network namespace: only a loopback, so one slot can never
                    // reach a service another slot (or the main agent) listens on.
                    // Egress goes through the bridge's unix socket (bridge::relay_to_unix).
                    | nix::sched::CloneFlags::CLONE_NEWNET,
            ))?;
            sys(nix::mount::mount::<CStr, CStr, CStr, CStr>(
                None,
                root.as_c_str(),
                None,
                nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                None,
            ))?;
            for (source, target) in [(&merged, &workspace), (&home, &agent_home), (&tmp, &tmp_target)] {
                sys(nix::mount::mount::<CStr, CStr, CStr, CStr>(
                    Some(source.as_c_str()),
                    target.as_c_str(),
                    None,
                    nix::mount::MsFlags::MS_BIND,
                    None,
                ))?;
            }
            // Hide every slot, the main upper and the control sockets.
            sys(nix::mount::mount::<CStr, CStr, CStr, CStr>(
                Some(tmpfs.as_c_str()),
                run_bulge.as_c_str(),
                Some(tmpfs.as_c_str()),
                nix::mount::MsFlags::empty(),
                Some(tmpfs_data.as_c_str()),
            ))?;
            if listener_fd != 3 && nix::libc::dup2(listener_fd, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::fcntl(3, nix::libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().map_err(SlotError::failed)
}

/// `sandboxd --slot-holder <n>` (stage 2): runs as root inside the slot's mount
/// namespace but outside its PID namespace (`unshare(CLONE_NEWPID)` only moves
/// children). It forks PID 1 of the slot's PID namespace, which mounts a /proc
/// that shows only the slot's processes, applies limits, drops to the workspace
/// owner with `no_new_privs`, and execs the slot server (stage 3). The holder
/// just waits and mirrors the server's exit; when PID 1 dies the kernel kills
/// every process left in the slot. Synchronous and single-threaded.
#[allow(unsafe_code)] // fork + exec of the namespace's PID 1 (see SAFETY below)
pub fn holder_main(slot: u8) -> Result<(), String> {
    validate_slot(slot)?;
    let uid = env_number("BULGE_BASE_UID")?;
    let gid = env_number("BULGE_BASE_GID")?;
    let proc_fs = CString::new("proc").map_err(|e| e.to_string())?;
    let proc_target = CString::new("/proc").map_err(|e| e.to_string())?;
    // SAFETY: this process is single-threaded (no runtime has started).
    match unsafe { nix::unistd::fork() }.map_err(|e| format!("fork slot init: {e}"))? {
        nix::unistd::ForkResult::Parent { child } => loop {
            match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => std::process::exit(code),
                Ok(nix::sys::wait::WaitStatus::Signaled(..)) => std::process::exit(1),
                Ok(_) => continue,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(format!("wait slot init: {error}")),
            }
        },
        nix::unistd::ForkResult::Child => {
            let result = (|| -> Result<std::convert::Infallible, String> {
                nix::mount::mount::<CStr, CStr, CStr, CStr>(
                    Some(proc_fs.as_c_str()),
                    proc_target.as_c_str(),
                    Some(proc_fs.as_c_str()),
                    nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
                    None,
                )
                .map_err(|e| format!("mount slot /proc: {e}"))?;
                // The new network namespace starts with loopback down.
                let up = std::process::Command::new("/sbin/ip")
                    .args(["link", "set", "lo", "up"])
                    .status()
                    .map_err(|e| format!("bring up slot loopback: {e}"))?;
                if !up.success() {
                    return Err(format!("bring up slot loopback: {up}"));
                }
                nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NPROC, 512, 512).map_err(|e| format!("rlimit: {e}"))?;
                nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, 4096, 4096).map_err(|e| format!("rlimit: {e}"))?;
                let gid = nix::unistd::Gid::from_raw(gid);
                nix::unistd::setgroups(&[gid]).map_err(|e| format!("setgroups: {e}"))?;
                nix::unistd::setresgid(gid, gid, gid).map_err(|e| format!("setresgid: {e}"))?;
                let uid = nix::unistd::Uid::from_raw(uid);
                nix::unistd::setresuid(uid, uid, uid).map_err(|e| format!("setresuid: {e}"))?;
                nix::sys::prctl::set_no_new_privs().map_err(|e| format!("no_new_privs: {e}"))?;
                let exe = CString::new("/proc/self/exe").map_err(|e| e.to_string())?;
                let args = [exe.clone(), CString::new("--slot-server").map_err(|e| e.to_string())?, CString::new(slot.to_string()).map_err(|e| e.to_string())?];
                nix::unistd::execv(&exe, &args).map_err(|e| format!("exec slot server: {e}"))
            })();
            // execv only returns on failure.
            let Err(message) = result;
            eprintln!("sandboxd: slot {slot} init: {message}");
            std::process::exit(1);
        }
    }
}

pub(crate) fn env_number(name: &str) -> Result<u32, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))?.parse().map_err(|e| format!("{name}: {e}"))
}

pub(crate) fn cleanup_slot(paths: &SlotPaths) -> Result<(), SlotError> {
    let merged = cstring(&paths.merged)?;
    match nix::mount::umount2(merged.as_c_str(), nix::mount::MntFlags::MNT_DETACH) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOENT) => {}
        Err(error) => return Err(SlotError::failed(format!("unmount {}: {error}", paths.merged.display()))),
    }
    match std::fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SlotError::failed(error)),
    }
    match std::fs::remove_dir_all(&paths.root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SlotError::failed(error)),
    }
    Ok(())
}
