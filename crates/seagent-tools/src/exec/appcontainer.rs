//! Windows stand-in for Landlock / Seatbelt (docs/cross-platform.md): commands run inside an
//! **AppContainer** with the same policy model as the `seatbelt` and `landlock` backends —
//! read roots, write roots, network on / off.
//!
//! * **Profile** — one AppContainer profile per agent workspace (and access mode), named
//!   `SEAgent.ws.<hash>` ([`profile_name`]): `CreateAppContainerProfile`, or
//!   `DeriveAppContainerSidFromAppContainerName` when it already exists. Sessions sharing a
//!   workspace share the container SID (so they can read each other's private temp dirs —
//!   the same trade-off as `scope = "agent"`).
//! * **Files** — an AppContainer can read only what `ALL APPLICATION PACKAGES` (or its own SID)
//!   is granted: `%SystemRoot%` and `Program Files` are, the user profile, other drives and the
//!   seagent data dir are not. The container SID gets an inheritable ACE
//!   (`SetEntriesInAclW` + `SetNamedSecurityInfoW`) on every write root (the workspace unless
//!   read-only, the private temp dir, read-write binds) and on read roots outside the
//!   default-readable locations (a read-only workspace, read-only binds / credential files,
//!   a per-user Git Bash install). See [`grants`].
//! * **Network** — no capability SIDs: no network at all (loopback included). With
//!   `network = "host"` only `internetClient` (outbound internet); LAN servers and loopback
//!   stay blocked (AppContainer loopback isolation).
//! * **Launch** — `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT` and one attribute list:
//!   `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, plus `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
//!   (only the stdio pipe ends are inherited) or `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` (ConPTY
//!   for `pty` requests). The process starts **suspended**, is put in its own kill-on-close
//!   Job Object (with UI restrictions: no clipboard, desktop switching, display settings,
//!   global atoms, shutdown), and only then resumed — nothing it starts can escape the job.
//! * **Shell** — the platform's active shell (`seagent_core::platform::shell`): Git Bash
//!   under Program Files is readable as-is; a per-user install (`%LOCALAPPDATA%\Programs\Git`)
//!   gets a read grant on its install root. PowerShell lives under `%SystemRoot%`. `HOME`,
//!   `TMP`, `TEMP` and `TMPDIR` point at the private temp dir.
//! * **Detached** commands run under a small wrapper inside the container (same shell) that
//!   writes the exit code to the pre-created exit file, which alone is granted to the container;
//!   output goes to an inherited handle of the log file. They are kept out of the job so they
//!   survive an seagent restart, as with the `local` backend.
//!
//! **Fallback.** When no AppContainer profile can be created (policy, very old Windows,
//! seagent itself running in an AppContainer), the backend says so and runs commands with a
//! *restricted token* instead: `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` at **low
//! integrity** (`SetTokenInformation(TokenIntegrityLevel)`) in the same job. Write roots are
//! labelled low-integrity so they stay writable; everything medium-labelled (the rest of the
//! user's files) is not. Reads are **not** confined and the network is **not** restricted —
//! [`ExecBackend::describe`] and a startup warning say exactly that; it is never reported as
//! an AppContainer. `auto` only picks this backend when the AppContainer probe succeeds.
//!
//! **Cleanup / reuse.** Grants are applied when the backend is built and revoked in
//! `cleanup()` (session reset, `seagent sandbox recreate`, shutdown): this backend's own temp
//! dir at once, the shared roots and the profile itself (`DeleteAppContainerProfile`) when the
//! last backend using that profile goes. Applying or revoking an inheritable ACE rewrites the
//! ACL of every file below the root, which takes a while on very large workspaces.
//!
//! **Not verified on a real Windows machine yet** (cross-compiled `cargo check` only). Known
//! risks: MSYS2 / Git Bash may need extra named-object or registry access inside an
//! AppContainer (`SEAGENT_SHELL` can point at PowerShell instead); tools that stat the parent
//! directories of the workspace (`C:\Users\<me>`) see access denied there. Each command's job
//! is also registered with the core process registry (`proc::adopt_job`), so the kernel
//! reaper's `kill_group(pid)` ends the whole tree, as it does for the `local` backend.

#![cfg_attr(not(windows), allow(dead_code))]

use super::local::Layout;
use seagent_core::platform::shell::ShellKind;
use std::path::{Path, PathBuf};

// ───────────── the policy (pure: tested on every OS) ─────────────

const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
const DELETE: u32 = 0x0001_0000;

/// `internetClient`: outbound connections to the internet (not LAN, not loopback).
pub(super) const INTERNET_CLIENT: &str = "S-1-15-3-1";

/// What the plan says about an AppContainer (`exec::os_plan`).
pub const WARNING: &str = "OS sandbox (Windows AppContainer): shares the host kernel, file access limited to system files, Program Files, the workspace and a private temp dir; user profile unreadable; network only with internetClient. One kernel or sandbox bug from the host; weaker than a microVM.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Access {
    Read,
    Write,
}

impl Access {
    /// The file rights an ACE for this access carries (read = read + execute / traverse;
    /// write = "modify": also write and delete, never `WRITE_DAC` / `WRITE_OWNER`).
    pub(super) fn mask(self) -> u32 {
        match self {
            Access::Read => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            Access::Write => FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        }
    }
}

/// One ACE the backend adds (and later revokes). `shared`: owned by the profile (workspace,
/// binds, shell), not by one backend (its private temp dir).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Grant {
    pub path: PathBuf,
    pub access: Access,
    pub shared: bool,
}

/// Read roots, write roots, network: the policy every OS sandbox backend carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Policy {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub network: bool,
    /// The private temp dir (a write root that belongs to this backend alone).
    pub tmp: PathBuf,
}

/// The policy for `l`; `shell_root` is the shell's install tree ([`shell_root`]).
pub(super) fn policy(l: &Layout, shell_root: Option<&Path>) -> Policy {
    let mut read = vec![];
    let mut write = vec![l.tmp.clone()];
    if l.writable {
        write.push(l.workspace.clone());
    } else {
        read.push(l.workspace.clone());
    }
    for (src, _, ro) in &l.binds {
        if *ro {
            read.push(src.clone());
        } else {
            write.push(src.clone());
        }
    }
    read.extend(shell_root.map(Path::to_path_buf));
    Policy { read, write, network: l.network, tmp: l.tmp.clone() }
}

/// A Windows path compared the way the file system does: `\` separators, no trailing `\`,
/// case-insensitive.
fn norm(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\").to_lowercase();
    let t = s.trim_end_matches('\\');
    if t.ends_with(':') {
        format!("{t}\\")
    } else {
        t.to_string()
    }
}

/// Is `p` `root` or below it?
fn under(p: &Path, root: &Path) -> bool {
    let (p, r) = (norm(p), norm(root));
    p == r || p.starts_with(&format!("{}\\", r.trim_end_matches('\\')))
}

/// Directories every AppContainer can already read (`ALL APPLICATION PACKAGES` has read +
/// execute there by default): Windows and Program Files.
pub(super) fn default_readable(env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().filter_map(|k| env(k)).filter(|v| !v.trim().is_empty()).map(PathBuf::from).collect()
}

/// The ACEs [`Policy`] needs: every write root, and every read root that is neither
/// default-readable nor inside a write root. Duplicates are dropped.
pub(super) fn grants(p: &Policy, default_readable: &[PathBuf]) -> Vec<Grant> {
    let mut out: Vec<Grant> = vec![];
    for w in &p.write {
        if !out.iter().any(|g| norm(&g.path) == norm(w)) {
            out.push(Grant { path: w.clone(), access: Access::Write, shared: norm(w) != norm(&p.tmp) });
        }
    }
    for r in &p.read {
        let covered = default_readable.iter().any(|d| under(r, d)) || p.write.iter().any(|w| under(r, w)) || out.iter().any(|g| norm(&g.path) == norm(r));
        if !covered {
            out.push(Grant { path: r.clone(), access: Access::Read, shared: true });
        }
    }
    out
}

/// Capability SIDs the container is started with: `internetClient` only when the network is
/// allowed, none otherwise.
pub(super) fn capabilities(network: bool) -> Vec<&'static str> {
    if network {
        vec![INTERNET_CLIENT]
    } else {
        vec![]
    }
}

/// The AppContainer profile of a workspace (≤ 64 characters, letters / digits / `.`): one per
/// workspace and access mode, so a read-only session never shares a SID that may write.
pub(super) fn profile_name(workspace: &Path, writable: bool) -> String {
    let key = format!("{}|{}", norm(workspace), if writable { "rw" } else { "ro" });
    format!("SEAgent.ws.{:016x}", super::fnv(key.as_bytes()))
}

/// The install tree a shell needs readable: `<root>` for Git Bash (`<root>\bin\bash.exe`) and
/// MSYS2 (`<root>\usr\bin\bash.exe`), else the program's own directory. Never a drive root and
/// never the user's home or one of its ancestors (a `bash.exe` in `~\bin` gets its directory
/// only). `None` for a bare name (looked up on `PATH`: System32 / Program Files).
pub(super) fn shell_root(program: &Path, user_home: Option<&Path>) -> Option<PathBuf> {
    let s = program.to_string_lossy().replace('/', "\\");
    let mut parts: Vec<&str> = s.split('\\').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    parts.pop();
    let dir = parts.join("\\");
    while parts.len() > 1 && matches!(parts.last().map(|p| p.to_ascii_lowercase()).as_deref(), Some("bin" | "usr")) {
        parts.pop();
    }
    let root = parts.join("\\");
    let too_wide = |r: &str| r.ends_with(':') || !r.contains('\\') || user_home.is_some_and(|h| under(h, Path::new(r)));
    if !too_wide(&root) {
        return Some(PathBuf::from(root));
    }
    (!too_wide(&dir)).then(|| PathBuf::from(dir))
}

/// Variables set for every sandboxed command: home and temp inside the private temp dir.
pub(super) fn sandbox_env(tmp: &Path) -> Vec<(String, String)> {
    let t = tmp.display().to_string();
    ["HOME", "TMP", "TEMP", "TMPDIR"].iter().map(|k| (k.to_string(), t.clone())).collect()
}

/// A `CreateProcessW` environment block: `K=V\0` per entry, then a final `\0`.
pub(super) fn env_block(vars: &[(Vec<u16>, Vec<u16>)]) -> Vec<u16> {
    let mut b = vec![];
    for (k, v) in vars {
        b.extend_from_slice(k);
        b.push('=' as u16);
        b.extend_from_slice(v);
        b.push(0);
    }
    if vars.is_empty() {
        b.push(0);
    }
    b.push(0);
    b
}

/// The Windows command line for `program` + `args` (`CommandLineToArgvW` quoting).
pub(super) fn command_line(program: &str, args: &[String]) -> String {
    seagent_core::platform::term::windows_command_line(program, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// POSIX wrapper of a detached command: run the script in the same shell, write its status
/// into the exit file (the only file outside the workspace the container may write).
const POSIX_DETACH: &str = "f=$SEAGENT_EXIT_FILE; c=$SEAGENT_DETACH_SCRIPT; o=$SEAGENT_DETACH_FLAG; unset SEAGENT_EXIT_FILE SEAGENT_DETACH_SCRIPT SEAGENT_DETACH_FLAG; \"$0\" \"$o\" \"$c\"; s=$?; printf '%s' \"$s\" > \"$f\"";

/// PowerShell wrapper: the script travels base64-encoded (`-EncodedCommand`), so Windows
/// PowerShell's argument passing never re-quotes it.
const PS_DETACH: &str = "$f=$env:SEAGENT_EXIT_FILE; $p=$env:SEAGENT_DETACH_SHELL; $c=$env:SEAGENT_DETACH_B64; $a=@('-NonInteractive'); \
if ($env:SEAGENT_DETACH_PROFILE -ne '1') { $a=@('-NoProfile')+$a }; \
Remove-Item Env:SEAGENT_EXIT_FILE,Env:SEAGENT_DETACH_SHELL,Env:SEAGENT_DETACH_B64,Env:SEAGENT_DETACH_PROFILE -ErrorAction SilentlyContinue; \
$s=1; try { & $p @a -EncodedCommand $c; $s=$LASTEXITCODE; if ($null -eq $s) { $s=0 } } catch { [Console]::Error.WriteLine($_.Exception.Message) }; \
[System.IO.File]::WriteAllText($f,[string]$s)";

/// `(args, env)` that make `program` (a shell of `kind`) run `script` detached and write its
/// exit status to `exit_file`.
pub(super) fn detach_wrapper(kind: ShellKind, program: &Path, script: &str, login: bool, exit_file: &Path) -> (Vec<String>, Vec<(String, String)>) {
    let exit = ("SEAGENT_EXIT_FILE".to_string(), exit_file.display().to_string());
    if kind.is_posix() {
        let flag = if login && kind == ShellKind::Bash { "-lc" } else { "-c" };
        let args = vec!["-c".into(), POSIX_DETACH.into(), program.display().to_string()];
        (args, vec![exit, ("SEAGENT_DETACH_SCRIPT".into(), script.into()), ("SEAGENT_DETACH_FLAG".into(), flag.into())])
    } else {
        use base64::Engine as _;
        let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
        let args = ["-NoProfile", "-NonInteractive", "-Command", PS_DETACH].map(String::from).to_vec();
        (args, vec![exit, ("SEAGENT_DETACH_SHELL".into(), program.display().to_string()), ("SEAGENT_DETACH_B64".into(), b64), ("SEAGENT_DETACH_PROFILE".into(), if login { "1" } else { "0" }.into())])
    }
}

/// The shell sandboxed commands run in. MSYS2 / Git Bash cannot start inside an AppContainer
/// or at low integrity: its runtime creates `\BaseNamedObjects\msys-*` with
/// `NtCreateDirectoryObject`, which is denied there (`fatal error … 0xC0000022`, exit
/// 0xC0000142). So when the host shell is such a bash, the sandbox uses Windows PowerShell
/// (in System32, readable by every AppContainer) and says so to the model;
/// `SEAGENT_APPCONTAINER_SHELL` names another shell (a self-contained `bash.exe`, `pwsh`).
pub fn sandbox_shell() -> seagent_core::platform::shell::Shell {
    use seagent_core::platform::shell::{active, detect_windows_with, Shell};
    if let Some(s) = std::env::var("SEAGENT_APPCONTAINER_SHELL").ok().filter(|s| !s.trim().is_empty()) {
        let env = |k: &str| (k == "SEAGENT_SHELL").then(|| s.clone());
        let mut sh = detect_windows_with(&env, &|_| false, &|_| None);
        sh.reason = "SEAGENT_APPCONTAINER_SHELL".into();
        return sh;
    }
    let sh = active();
    if !sh.kind.is_posix() {
        return sh.clone();
    }
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    Shell { kind: ShellKind::WindowsPowerShell, program: root.join("System32\\WindowsPowerShell\\v1.0\\powershell.exe"), reason: format!("{} cannot start inside an AppContainer (MSYS runtime); Windows PowerShell instead", sh.program.display()) }
}

/// PowerShell inside an AppContainer starts in `C:\` (it cannot traverse the workspace's
/// parents to adopt the process directory), so its script begins with `Set-Location` there.
/// POSIX shells keep the process directory as is.
pub(super) fn in_dir(kind: ShellKind, cwd: &Path, script: &str) -> String {
    if kind.is_posix() {
        return script.to_string();
    }
    let d = cwd.display().to_string().replace('\'', "''");
    format!("$null = New-PSDrive -Name SeagentWs -PSProvider FileSystem -Root '{d}' -Scope Global -ErrorAction SilentlyContinue; Set-Location SeagentWs:\\ -ErrorAction SilentlyContinue; [Environment]::CurrentDirectory = '{d}'\n{script}")
}

/// Can this machine create AppContainers? (Probed once: create + delete a probe profile.)
/// Always false off Windows.
pub fn available() -> bool {
    #[cfg(windows)]
    {
        win::probe().is_ok()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
pub use win::AppContainerBackend;

// ───────────── Windows ─────────────

#[cfg(windows)]
mod win {
    use super::*;
    use crate::exec::local::{drop_odd_named_secrets, layout, proc_start_time, register_child};
    use crate::exec::local_windows::{creation_flags, full_env, Console, Detached, LocalChild, Output, WinProc};
    use crate::exec::sandbox::SandboxConfig;
    use crate::exec::BackendCtx;
    use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
    use std::collections::HashMap;
    use std::ffi::{c_void, OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, SetHandleInformation, ERROR_ACCESS_DENIED, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, PSID, WAIT_OBJECT_0};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SDDL_REVISION_1, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName};
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, FreeSid, GetLengthSid, GetSecurityDescriptorSacl, SetTokenInformation, TokenIntegrityLevel, ACL, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_ADJUST_DEFAULT,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Console::{ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    /// `SE_GROUP_ENABLED` / `SE_GROUP_INTEGRITY` (windows-sys has them under SystemServices).
    const SE_GROUP_ENABLED: u32 = 0x4;
    const SE_GROUP_INTEGRITY: u32 = 0x20;
    /// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
    const HR_ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;
    const LOW_INTEGRITY: &str = "S-1-16-4096";

    fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
        s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// An owned kernel handle.
    struct Owned(HANDLE);
    // SAFETY: kernel handles are usable from any thread.
    unsafe impl Send for Owned {}
    unsafe impl Sync for Owned {}
    impl Drop for Owned {
        fn drop(&mut self) {
            if self.0 != 0 && self.0 != -1 {
                // SAFETY: we own the handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// A SID from `ConvertStringSidToSidW` (`LocalFree`) or the AppContainer API (`FreeSid`).
    struct Sid {
        p: PSID,
        local: bool,
    }
    // SAFETY: the SID is never written after creation.
    unsafe impl Send for Sid {}
    unsafe impl Sync for Sid {}
    impl Drop for Sid {
        fn drop(&mut self) {
            // SAFETY: allocated by the API named in `local`.
            unsafe {
                if self.local {
                    LocalFree(self.p as HLOCAL);
                } else {
                    FreeSid(self.p);
                }
            }
        }
    }

    fn string_sid(s: &str) -> Result<Sid, String> {
        let w = wide(s);
        let mut p: PSID = std::ptr::null_mut();
        // SAFETY: NUL-terminated input, out-parameter.
        if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut p) } == 0 {
            return Err(format!("ConvertStringSidToSid({s}): {}", io::Error::last_os_error()));
        }
        Ok(Sid { p, local: true })
    }

    /// The SID of profile `name`, creating the profile when it does not exist yet.
    fn container_sid(name: &str) -> Result<Sid, String> {
        let w = wide(name);
        let display = wide("SEAgent sandbox");
        let desc = wide("SEAgent command sandbox (one per workspace)");
        let mut p: PSID = std::ptr::null_mut();
        // SAFETY: NUL-terminated strings, no capabilities, out-parameter.
        let mut hr = unsafe { CreateAppContainerProfile(w.as_ptr(), display.as_ptr(), desc.as_ptr(), std::ptr::null(), 0, &mut p) };
        if hr == HR_ALREADY_EXISTS {
            // SAFETY: as above.
            hr = unsafe { DeriveAppContainerSidFromAppContainerName(w.as_ptr(), &mut p) };
        }
        if hr < 0 || p.is_null() {
            return Err(format!("CreateAppContainerProfile({name}) failed (HRESULT {hr:#010x})"));
        }
        Ok(Sid { p, local: false })
    }

    fn delete_profile(name: &str) {
        let w = wide(name);
        // SAFETY: NUL-terminated name.
        unsafe { DeleteAppContainerProfile(w.as_ptr()) };
    }

    pub(super) fn probe() -> Result<(), String> {
        static P: OnceLock<Result<(), String>> = OnceLock::new();
        P.get_or_init(|| {
            let name = format!("SEAgent.probe.{}", std::process::id());
            let r = container_sid(&name).map(drop);
            delete_profile(&name);
            r
        })
        .clone()
    }

    /// Add (`GRANT_ACCESS`) or remove (`REVOKE_ACCESS`) the ACE of `sid` on `path`; inheritable
    /// to everything below a directory.
    fn set_acl(path: &Path, sid: PSID, access: Access, mode: ACCESS_MODE) -> Result<(), String> {
        let w = wide(path.as_os_str());
        let inherit = if path.is_dir() { SUB_CONTAINERS_AND_OBJECTS_INHERIT } else { 0 };
        // SAFETY: out-parameters from GetNamedSecurityInfoW live in `sd` until LocalFree; the
        // new ACL is freed after SetNamedSecurityInfoW copied it.
        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let e = GetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut sd);
            if e != 0 {
                return Err(format!("read the ACL of {}: {}", path.display(), io::Error::from_raw_os_error(e as i32)));
            }
            let ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: access.mask(),
                grfAccessMode: mode,
                grfInheritance: inherit,
                Trustee: TRUSTEE_W { pMultipleTrustee: std::ptr::null_mut(), MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE, TrusteeForm: TRUSTEE_IS_SID, TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP, ptstrName: sid as *mut u16 },
            };
            let mut new: *mut ACL = std::ptr::null_mut();
            let e = SetEntriesInAclW(1, &ea, dacl, &mut new);
            LocalFree(sd as HLOCAL);
            if e != 0 {
                return Err(format!("build the ACL of {}: {}", path.display(), io::Error::from_raw_os_error(e as i32)));
            }
            let e = SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), new, std::ptr::null());
            LocalFree(new as HLOCAL);
            if e != 0 {
                return Err(format!("set the ACL of {}: {}", path.display(), io::Error::from_raw_os_error(e as i32)));
            }
        }
        Ok(())
    }

    /// Set the mandatory label of `path` (`LW` low, `ME` medium = the default), inheritable.
    fn set_label(path: &Path, level: &str) -> Result<(), String> {
        let sddl = wide(if path.is_dir() { format!("S:(ML;OICI;NW;;;{level})") } else { format!("S:(ML;;NW;;;{level})") });
        let w = wide(path.as_os_str());
        // SAFETY: the SACL points into `sd`, which is freed after SetNamedSecurityInfoW.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
                return Err(format!("label SDDL: {}", io::Error::last_os_error()));
            }
            let (mut present, mut defaulted) = (0, 0);
            let mut sacl: *mut ACL = std::ptr::null_mut();
            let ok = GetSecurityDescriptorSacl(sd, &mut present, &mut sacl, &mut defaulted);
            let e = if ok == 0 { GetLastError() } else { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), sacl) };
            LocalFree(sd as HLOCAL);
            if e != 0 {
                return Err(format!("label {} {level}: {}", path.display(), io::Error::from_raw_os_error(e as i32)));
            }
        }
        Ok(())
    }

    /// A primary token with every privilege but `SeChangeNotifyPrivilege` removed, at low
    /// integrity.
    fn restricted_token() -> Result<Owned, String> {
        // SAFETY: plain token calls on handles we own; `tml` and the SID outlive the call.
        unsafe {
            let mut t: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &mut t) == 0 {
                return Err(format!("OpenProcessToken: {}", io::Error::last_os_error()));
            }
            let t = Owned(t);
            let mut r: HANDLE = 0;
            if CreateRestrictedToken(t.0, DISABLE_MAX_PRIVILEGE, 0, std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), &mut r) == 0 {
                return Err(format!("CreateRestrictedToken: {}", io::Error::last_os_error()));
            }
            let r = Owned(r);
            let low = string_sid(LOW_INTEGRITY)?;
            let tml = TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: low.p, Attributes: SE_GROUP_INTEGRITY } };
            let len = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low.p);
            if SetTokenInformation(r.0, TokenIntegrityLevel, (&tml as *const TOKEN_MANDATORY_LABEL).cast(), len) == 0 {
                return Err(format!("SetTokenInformation(TokenIntegrityLevel): {}", io::Error::last_os_error()));
            }
            Ok(r)
        }
    }

    /// A kill-on-close job with UI restrictions for one command tree.
    fn new_job() -> io::Result<Owned> {
        // SAFETY: plain calls; the info structs outlive SetInformationJobObject.
        unsafe {
            let job = Owned(CreateJobObjectW(std::ptr::null(), std::ptr::null()));
            if job.0 == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            if SetInformationJobObject(job.0, JobObjectExtendedLimitInformation, (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32) == 0 {
                return Err(io::Error::last_os_error());
            }
            let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS | JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            };
            // Best-effort: the kill-on-close limit above is what must hold.
            SetInformationJobObject(job.0, JobObjectBasicUIRestrictions, (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(), std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32);
            Ok(job)
        }
    }

    fn job_active(job: HANDLE) -> u32 {
        // SAFETY: zeroed POD out-parameter of the size we pass.
        unsafe {
            let mut a: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
            let ok = QueryInformationJobObject(job, JobObjectBasicAccountingInformation, (&mut a as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32, std::ptr::null_mut());
            if ok == 0 {
                0
            } else {
                a.ActiveProcesses
            }
        }
    }

    /// Jobs whose leader exited while background members still run: kept open (as the core
    /// job registry does for the `local` backend) until they are empty or seagent exits.
    fn linger(job: Owned) {
        static L: OnceLock<Mutex<Vec<Owned>>> = OnceLock::new();
        let mut v = L.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
        v.retain(|j| job_active(j.0) > 0);
        if job_active(job.0) > 0 {
            v.push(job);
        }
    }

    /// One process started by this backend.
    struct AcProc {
        process: Owned,
        pid: u32,
        job: Option<Owned>,
    }

    impl WinProc for AcProc {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn exit_code(&mut self) -> io::Result<Option<i32>> {
            // SAFETY: owned process handle and out-parameter.
            unsafe {
                if WaitForSingleObject(self.process.0, 0) != WAIT_OBJECT_0 {
                    return Ok(None);
                }
                let mut code = 0u32;
                if GetExitCodeProcess(self.process.0, &mut code) == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(code as i32))
            }
        }
        fn terminate(&mut self) {
            // SAFETY: owned handles.
            unsafe {
                match &self.job {
                    Some(j) => TerminateJobObject(j.0, 1),
                    None => TerminateProcess(self.process.0, 1),
                };
            }
        }
    }

    impl Drop for AcProc {
        fn drop(&mut self) {
            if let Some(j) = self.job.take() {
                linger(j);
            }
        }
    }

    /// A ConPTY pseudo console for one sandboxed command.
    struct Pty {
        hpc: HPCON,
        input: File,
        output: File,
    }
    // SAFETY: the console handle is usable from any thread.
    unsafe impl Send for Pty {}

    impl Pty {
        fn open(rows: u16, cols: u16) -> io::Result<Pty> {
            // SAFETY: pipe handles are created, handed to ConPTY (which duplicates its ends) and
            // the ends we keep become owned Files.
            unsafe {
                let (mut in_r, mut in_w, mut out_r, mut out_w) = (0, 0, 0, 0);
                if CreatePipe(&mut in_r, &mut in_w, std::ptr::null(), 0) == 0 {
                    return Err(io::Error::last_os_error());
                }
                if CreatePipe(&mut out_r, &mut out_w, std::ptr::null(), 0) == 0 {
                    let e = io::Error::last_os_error();
                    CloseHandle(in_r);
                    CloseHandle(in_w);
                    return Err(e);
                }
                let mut hpc: HPCON = 0;
                let hr = CreatePseudoConsole(COORD { X: cols.max(1) as i16, Y: rows.max(1) as i16 }, in_r, out_w, 0, &mut hpc);
                CloseHandle(in_r);
                CloseHandle(out_w);
                let input = File::from_raw_handle(in_w as RawHandle);
                let output = File::from_raw_handle(out_r as RawHandle);
                if hr != 0 {
                    return Err(io::Error::other(format!("CreatePseudoConsole failed (HRESULT {hr:#x})")));
                }
                Ok(Pty { hpc, input, output })
            }
        }
    }

    impl Console for Pty {
        fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
            // SAFETY: live pseudo console handle.
            let hr = unsafe { ResizePseudoConsole(self.hpc, COORD { X: cols.max(1) as i16, Y: rows.max(1) as i16 }) };
            if hr != 0 {
                return Err(io::Error::other(format!("ResizePseudoConsole failed (HRESULT {hr:#x})")));
            }
            Ok(())
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            // SAFETY: we own the pseudo console handle.
            unsafe { ClosePseudoConsole(self.hpc) };
        }
    }

    /// Where the child's standard handles come from.
    #[derive(Clone, Copy)]
    enum Stdio {
        /// Inheritable pipe / file handles: stdin, stdout (= stderr).
        Handles(HANDLE, HANDLE),
        Console(HPCON),
    }

    enum Mode {
        Container { sid: Sid, caps: Vec<Sid> },
        Restricted { token: Owned, why: String },
    }

    /// How many live backends use each profile (shared grants are revoked by the last one).
    fn users() -> &'static Mutex<HashMap<String, usize>> {
        static U: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
        U.get_or_init(Default::default)
    }

    pub struct AppContainerBackend {
        l: Layout,
        name: String,
        mode: Mode,
        grants: Vec<Grant>,
        released: Mutex<bool>,
    }

    impl AppContainerBackend {
        pub fn new(sb: &SandboxConfig, ctx: &BackendCtx) -> Result<AppContainerBackend, String> {
            let l = layout(sb, ctx)?;
            let sh = seagent_core::platform::shell::active();
            let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
            let root = shell_root(&sh.program, home.as_deref());
            let pol = policy(&l, root.as_deref());
            let env = |k: &str| std::env::var(k).ok();
            let grants = grants(&pol, &default_readable(&env));
            let name = profile_name(&l.workspace, l.writable);
            let mode = match container_sid(&name) {
                Ok(sid) => {
                    for (i, g) in grants.iter().enumerate() {
                        if let Err(e) = set_acl(&g.path, sid.p, g.access, GRANT_ACCESS) {
                            // Leave nothing half-granted behind (shared roots stay while another
                            // backend uses this profile).
                            let others = users().lock().unwrap_or_else(|e| e.into_inner()).get(&name).is_some_and(|n| *n > 0);
                            for done in grants[..i].iter().filter(|d| !d.shared || !others) {
                                let _ = set_acl(&done.path, sid.p, done.access, REVOKE_ACCESS);
                            }
                            return Err(format!("exec backend appcontainer: cannot grant the sandbox access: {e}"));
                        }
                    }
                    let caps = capabilities(pol.network).into_iter().map(string_sid).collect::<Result<Vec<_>, _>>()?;
                    Mode::Container { sid, caps }
                }
                Err(why) => {
                    let token = restricted_token().map_err(|e| format!("exec backend appcontainer: no AppContainer ({why}) and no restricted token ({e}); use docker or vm"))?;
                    for g in grants.iter().filter(|g| g.access == Access::Write) {
                        set_label(&g.path, "LW").map_err(|e| format!("exec backend appcontainer (restricted-token fallback): {e}"))?;
                    }
                    super::super::warn_once("appcontainer-degraded", &format!("appcontainer: no AppContainer could be created ({why}); commands run with a restricted low-integrity token instead — LOWER ISOLATION: reads are not confined (home and keys readable) and the network is not restricted; use `vm` or `docker` for real isolation"));
                    Mode::Restricted { token, why }
                }
            };
            *users().lock().unwrap_or_else(|e| e.into_inner()).entry(name.clone()).or_insert(0) += 1;
            Ok(AppContainerBackend { l, name, mode, grants, released: Mutex::new(false) })
        }

        /// Start `line` suspended in the sandbox, put it in a fresh job (unless `detach`), resume.
        fn launch(&self, line: &str, cwd: &Path, env: &[(OsString, OsString)], stdio: Stdio, detach: bool) -> io::Result<AcProc> {
            let mut handles: Vec<HANDLE> = vec![];
            if let Stdio::Handles(i, o) = stdio {
                handles.push(i);
                if o != i {
                    handles.push(o);
                }
                for &h in &handles {
                    // SAFETY: valid handles we own; only the handle list below reaches the child.
                    if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            let count = 1 + matches!(self.mode, Mode::Container { .. }) as u32;
            // SAFETY: the attribute list lives in `attr` until DeleteProcThreadAttributeList; every
            // value it points at (`sc`, `caps`, `handles`, the console handle) outlives
            // CreateProcess; all strings are NUL-terminated.
            unsafe {
                let mut size = 0usize;
                InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size);
                let mut attr = vec![0u64; size.div_ceil(8).max(1)];
                let list = attr.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
                if InitializeProcThreadAttributeList(list, count, 0, &mut size) == 0 {
                    return Err(io::Error::last_os_error());
                }
                struct ListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
                impl Drop for ListGuard {
                    fn drop(&mut self) {
                        // SAFETY: initialised above.
                        unsafe { DeleteProcThreadAttributeList(self.0) };
                    }
                }
                let _guard = ListGuard(list);
                let mut caps: Vec<SID_AND_ATTRIBUTES> = match &self.mode {
                    Mode::Container { caps, .. } => caps.iter().map(|s| SID_AND_ATTRIBUTES { Sid: s.p, Attributes: SE_GROUP_ENABLED }).collect(),
                    Mode::Restricted { .. } => vec![],
                };
                let cap_ptr = if caps.is_empty() { std::ptr::null_mut() } else { caps.as_mut_ptr() };
                // UpdateProcThreadAttribute stores the pointer: `sc` lives until we return.
                let sc: Option<SECURITY_CAPABILITIES> = match &self.mode {
                    Mode::Container { sid, .. } => Some(SECURITY_CAPABILITIES { AppContainerSid: sid.p, Capabilities: cap_ptr, CapabilityCount: caps.len() as u32, Reserved: 0 }),
                    Mode::Restricted { .. } => None,
                };
                if let Some(sc) = &sc {
                    if UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize, (sc as *const SECURITY_CAPABILITIES).cast(), std::mem::size_of::<SECURITY_CAPABILITIES>(), std::ptr::null_mut(), std::ptr::null()) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                let mut si: STARTUPINFOEXW = std::mem::zeroed();
                si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
                si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                si.lpAttributeList = list;
                let mut flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
                let inherit = match stdio {
                    Stdio::Handles(i, o) => {
                        if UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, handles.as_ptr().cast(), handles.len() * std::mem::size_of::<HANDLE>(), std::ptr::null_mut(), std::ptr::null()) == 0 {
                            return Err(io::Error::last_os_error());
                        }
                        si.StartupInfo.hStdInput = i;
                        si.StartupInfo.hStdOutput = o;
                        si.StartupInfo.hStdError = o;
                        flags |= if detach { CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB } else { creation_flags() };
                        1
                    }
                    Stdio::Console(hpc) => {
                        // The value is the console handle itself (not a pointer to it).
                        if UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize, hpc as *const c_void, std::mem::size_of::<HPCON>(), std::ptr::null_mut(), std::ptr::null()) == 0 {
                            return Err(io::Error::last_os_error());
                        }
                        0
                    }
                };
                let mut cmd = wide(line);
                let cwd_w = wide(cwd.as_os_str());
                let block = env_block(&env.iter().map(|(k, v)| (k.encode_wide().collect(), v.encode_wide().collect())).collect::<Vec<_>>());
                let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
                let create = |flags: u32, pi: &mut PROCESS_INFORMATION, cmd: &mut Vec<u16>| match &self.mode {
                    Mode::Container { .. } => CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), inherit, flags, block.as_ptr().cast(), cwd_w.as_ptr(), &si.StartupInfo, pi),
                    Mode::Restricted { token, .. } => CreateProcessAsUserW(token.0, std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), inherit, flags, block.as_ptr().cast(), cwd_w.as_ptr(), &si.StartupInfo, pi),
                };
                let mut ok = create(flags, &mut pi, &mut cmd);
                if ok == 0 && flags & CREATE_BREAKAWAY_FROM_JOB != 0 && GetLastError() == ERROR_ACCESS_DENIED {
                    // seagent's own job forbids breaking away: the detached command stays in it.
                    ok = create(flags & !CREATE_BREAKAWAY_FROM_JOB, &mut pi, &mut cmd);
                }
                let err = io::Error::last_os_error();
                for &h in &handles {
                    SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
                }
                if ok == 0 {
                    return Err(err);
                }
                let thread = Owned(pi.hThread);
                let mut p = AcProc { process: Owned(pi.hProcess), pid: pi.dwProcessId, job: None };
                if !detach {
                    let job = new_job().and_then(|j| if AssignProcessToJobObject(j.0, pi.hProcess) == 0 { Err(io::Error::last_os_error()) } else { Ok(j) });
                    match job {
                        Ok(j) => {
                            // Also known to the core registry, so `kill_group(pid)` (the kernel
                            // reaper) ends the whole tree, not only the leader. Best-effort: the
                            // job we keep already ties the tree to seagent.
                            let _ = seagent_core::platform::proc::adopt_job(j.0 as RawHandle, pi.dwProcessId);
                            p.job = Some(j);
                        }
                        Err(e) => {
                            TerminateProcess(pi.hProcess, 1);
                            return Err(io::Error::other(format!("cannot put pid {} in a job object: {e}", pi.dwProcessId)));
                        }
                    }
                }
                if ResumeThread(thread.0) == u32::MAX {
                    let e = io::Error::last_os_error();
                    p.terminate();
                    return Err(e);
                }
                Ok(p)
            }
        }

        fn cwd(&self, req: &ExecRequest) -> PathBuf {
            req.cwd.clone().filter(|c| c.starts_with(&self.l.workspace)).unwrap_or_else(|| self.l.workspace.clone())
        }

        /// The environment of a sandboxed command: ours minus odd-named secrets, the request's,
        /// then home / temp in the private temp dir.
        fn env(&self, cmd: &mut Command, req: &ExecRequest, extra: &[(String, String)]) -> Vec<(OsString, OsString)> {
            drop_odd_named_secrets(cmd);
            for (k, v) in req.env.iter().chain(sandbox_env(&self.l.tmp).iter()).chain(extra) {
                cmd.env(k, v);
            }
            full_env(cmd)
        }

        fn spawn_attached(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
            // The sandbox's own shell (PowerShell when the host shell is MSYS bash).
            let sh = super::sandbox_shell();
            let cwd = self.cwd(req);
            let script = super::in_dir(sh.kind, &cwd, &req.script);
            let mut cmd = seagent_core::platform::proc::command(&sh.program);
            cmd.args(sh.args(seagent_core::platform::shell::Style::bash(req.login), &script));
            let env = self.env(&mut cmd, req, &[]);
            let line = crate::exec::local_windows::command_line(&cmd);
            if let Some((rows, cols)) = req.pty {
                let pty = Pty::open(rows, cols)?;
                let p = self.launch(&line, &cwd, &env, Stdio::Console(pty.hpc), false)?;
                register_child(p.pid, "");
                let out = Output::spawn(pty.output.try_clone()?)?;
                let input: Box<dyn Write + Send> = Box::new(pty.input.try_clone()?);
                let mut c = LocalChild::from_parts(Box::new(p), Some(out), Some(input), Some(Box::new(pty)));
                c.feed(req)?;
                return Ok(Box::new(c));
            }
            let (r, w) = std::io::pipe()?;
            let keep_stdin = req.stdin || req.stdin_data.is_some();
            let (child_in, ours): (File, Option<std::io::PipeWriter>) = if keep_stdin {
                let (cr, cw) = std::io::pipe()?;
                (File::from(std::os::windows::io::OwnedHandle::from(cr)), Some(cw))
            } else {
                (File::open("NUL")?, None)
            };
            let p = self.launch(&line, &cwd, &env, Stdio::Handles(child_in.as_raw_handle() as HANDLE, w.as_raw_handle() as HANDLE), false)?;
            // Our copies of the child's ends: EOF once the command's tree is done.
            drop(w);
            drop(child_in);
            register_child(p.pid, "");
            let stdin = ours.map(|s| Box::new(s) as Box<dyn Write + Send>);
            let mut c = LocalChild::from_parts(Box::new(p), Some(Output::spawn(r)?), stdin, None);
            c.feed(req)?;
            Ok(Box::new(c))
        }

        fn spawn_detached(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
            let log = req.log_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs log_file"))?;
            let exit = req.exit_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs exit_file"))?;
            // Pre-created empty (read as "still running"); the container may write this file only.
            std::fs::write(&exit, b"")?;
            let grant = match &self.mode {
                Mode::Container { sid, .. } => set_acl(&exit, sid.p, Access::Write, GRANT_ACCESS),
                Mode::Restricted { .. } => set_label(&exit, "LW"),
            };
            grant.map_err(io::Error::other)?;
            // Not append-only: Git Bash exits 1 at startup on one (`open_child_log`).
            let out = seagent_core::platform::proc::open_child_log(&log)?;
            let sh = super::sandbox_shell();
            let script = super::in_dir(sh.kind, &self.cwd(req), &req.script);
            let (args, wrap_env) = detach_wrapper(sh.kind, &sh.program, &script, req.login, &exit);
            let mut cmd = seagent_core::platform::proc::command(&sh.program);
            let env = self.env(&mut cmd, req, &wrap_env);
            let line = command_line(&sh.program.to_string_lossy(), &args);
            let nul = File::open("NUL")?;
            let p = self.launch(&line, &self.cwd(req), &env, Stdio::Handles(nul.as_raw_handle() as HANDLE, out.as_raw_handle() as HANDLE), true)?;
            drop(out);
            let pid = p.pid;
            register_child(pid, "detached");
            let mut c = LocalChild::from_parts(Box::new(p), None, None, None);
            c.detached = Some(Detached { pid, log: File::open(&log)?, exit_file: exit, start: proc_start_time(pid) });
            Ok(Box::new(c))
        }
    }

    impl ExecBackend for AppContainerBackend {
        fn id(&self) -> &str {
            "appcontainer"
        }
        fn describe(&self) -> String {
            let ws = format!("{} {}", self.l.workspace.display(), if self.l.writable { "read-write" } else { "read-only" });
            let shell = super::sandbox_shell().prompt_note();
            match &self.mode {
                Mode::Container { caps, .. } => format!(
                    "appcontainer: Windows AppContainer sandbox (profile {}); workspace {ws}, private temp {}; network {}; the user profile and other files are not readable (only Windows, Program Files and the granted roots); each command tree runs in a kill-on-close Job Object. Shares the host kernel. {shell}",
                    self.name,
                    self.l.tmp.display(),
                    if caps.is_empty() { "disabled (no capabilities, loopback included)" } else { "internet only (internetClient; LAN and loopback blocked)" },
                ),
                Mode::Restricted { why, .. } => format!(
                    "appcontainer (DEGRADED, NOT an AppContainer): {why}. Commands run with a restricted token (no privileges but traverse) at low integrity in a kill-on-close Job Object: writes are limited to the workspace {ws} and private temp {} (labelled low integrity) and other low-integrity locations; reads are NOT confined (home and keys readable); network is NOT restricted. Much weaker than an AppContainer. {shell}",
                    self.l.tmp.display()
                ),
            }
        }
        fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
            if req.detach {
                self.spawn_detached(req)
            } else {
                self.spawn_attached(req)
            }
        }
        fn temp_dir(&self) -> String {
            self.l.tmp.display().to_string()
        }
        /// Revoke this backend's grants; the shared ones and the profile go with the last user.
        fn cleanup(&self) {
            let mut done = self.released.lock().unwrap_or_else(|e| e.into_inner());
            if *done {
                return;
            }
            *done = true;
            let last = {
                let mut u = users().lock().unwrap_or_else(|e| e.into_inner());
                let n = u.entry(self.name.clone()).or_insert(1);
                *n = n.saturating_sub(1);
                let last = *n == 0;
                if last {
                    u.remove(&self.name);
                }
                last
            };
            for g in self.grants.iter().filter(|g| last || !g.shared) {
                let _ = match &self.mode {
                    Mode::Container { sid, .. } => set_acl(&g.path, sid.p, g.access, REVOKE_ACCESS),
                    Mode::Restricted { .. } if g.access == Access::Write => set_label(&g.path, "ME"),
                    Mode::Restricted { .. } => Ok(()),
                };
            }
            if last && matches!(self.mode, Mode::Container { .. }) {
                delete_profile(&self.name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(writable: bool, network: bool, binds: Vec<(PathBuf, String, bool)>) -> Layout {
        Layout { workspace: PathBuf::from("C:\\Users\\me\\proj"), writable, tmp: PathBuf::from("C:\\Users\\me\\AppData\\Local\\seagent\\sandbox\\s-1\\tmp"), binds, network }
    }

    fn defaults() -> Vec<PathBuf> {
        let env = |k: &str| match k {
            "SystemRoot" => Some("C:\\Windows".to_string()),
            "ProgramFiles" => Some("C:\\Program Files".to_string()),
            "ProgramFiles(x86)" => Some(String::new()),
            _ => None,
        };
        default_readable(&env)
    }

    #[test]
    fn write_roots_get_modify_read_roots_only_outside_default_readable() {
        let binds = vec![(PathBuf::from("C:\\Users\\me\\.gitconfig"), "/tmp/.gitconfig".into(), true), (PathBuf::from("D:\\cache"), "/cache".into(), false), (PathBuf::from("C:\\Program Files\\Tool"), "/tool".into(), true)];
        let l = layout(true, false, binds);
        let p = policy(&l, Some(Path::new("C:\\Users\\me\\AppData\\Local\\Programs\\Git")));
        assert_eq!(defaults(), vec![PathBuf::from("C:\\Windows"), PathBuf::from("C:\\Program Files")], "empty variables are ignored");
        let g = grants(&p, &defaults());
        let names: Vec<(String, Access, bool)> = g.iter().map(|g| (g.path.display().to_string(), g.access, g.shared)).collect();
        assert_eq!(
            names,
            vec![
                (l.tmp.display().to_string(), Access::Write, false),
                ("C:\\Users\\me\\proj".into(), Access::Write, true),
                ("D:\\cache".into(), Access::Write, true),
                ("C:\\Users\\me\\.gitconfig".into(), Access::Read, true),
                ("C:\\Users\\me\\AppData\\Local\\Programs\\Git".into(), Access::Read, true),
            ],
            "Program Files needs no grant; the per-user Git and the credential file do"
        );
        assert_eq!(Access::Read.mask() & FILE_GENERIC_WRITE & !FILE_GENERIC_READ & !FILE_GENERIC_EXECUTE, 0, "read never carries write bits");
        assert_eq!(Access::Write.mask() & 0x000C_0000, 0, "never WRITE_DAC / WRITE_OWNER");
        assert_ne!(Access::Write.mask() & DELETE, 0);
    }

    #[test]
    fn a_read_only_workspace_is_a_read_grant_and_paths_compare_like_windows() {
        let l = layout(false, true, vec![]);
        let p = policy(&l, None);
        assert!(p.network && p.write == vec![l.tmp.clone()] && p.read == vec![l.workspace.clone()]);
        let g = grants(&p, &defaults());
        assert_eq!(g.iter().find(|g| g.path == l.workspace).map(|g| g.access), Some(Access::Read));
        // Case and separators do not make a second grant; a path inside a write root needs none.
        let p = Policy { read: vec![PathBuf::from("c:/users/ME/proj/sub"), PathBuf::from("C:\\WINDOWS\\System32")], write: vec![PathBuf::from("C:\\Users\\me\\proj\\"), PathBuf::from("c:\\users\\me\\proj")], network: false, tmp: PathBuf::from("T:\\t") };
        assert_eq!(grants(&p, &defaults()).len(), 1);
        assert!(under(Path::new("C:\\a\\b"), Path::new("C:\\")) && !under(Path::new("C:\\ab"), Path::new("C:\\a")));
    }

    #[test]
    fn network_maps_to_internet_client_only() {
        assert_eq!(capabilities(false), Vec::<&str>::new());
        assert_eq!(capabilities(true), vec!["S-1-15-3-1"]);
    }

    #[test]
    fn profile_names_are_per_workspace_and_mode_and_fit_the_api() {
        let a = profile_name(Path::new("C:\\Users\\me\\proj"), true);
        assert_eq!(a, profile_name(Path::new("c:/users/me/proj/"), true), "same workspace, same profile");
        assert_ne!(a, profile_name(Path::new("C:\\Users\\me\\proj"), false), "read-only never shares a SID that may write");
        assert_ne!(a, profile_name(Path::new("C:\\Users\\me\\other"), true));
        assert!(a.len() <= 64 && a.starts_with("SEAgent.ws.") && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '.'), "{a}");
    }

    #[test]
    fn shell_roots() {
        let home = Path::new("C:\\Users\\me");
        let r = |p: &str| shell_root(Path::new(p), Some(home)).map(|p| p.display().to_string());
        assert_eq!(r("C:\\Program Files\\Git\\bin\\bash.exe").as_deref(), Some("C:\\Program Files\\Git"));
        assert_eq!(r("C:\\msys64\\usr\\bin\\bash.exe").as_deref(), Some("C:\\msys64"));
        assert_eq!(r("C:\\Users\\me\\AppData\\Local\\Programs\\Git\\bin\\bash.exe").as_deref(), Some("C:\\Users\\me\\AppData\\Local\\Programs\\Git"));
        // `~\bin\bash.exe` must not grant the whole home; a drive root is never granted.
        assert_eq!(r("C:\\Users\\me\\bin\\bash.exe").as_deref(), Some("C:\\Users\\me\\bin"));
        assert_eq!(r("C:\\bin\\bash.exe").as_deref(), Some("C:\\bin"));
        assert_eq!(r("C:\\bash.exe"), None);
        assert_eq!(r("powershell.exe"), None);
    }

    #[test]
    fn environment_and_command_line() {
        let env = sandbox_env(Path::new("C:\\t"));
        assert_eq!(env.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["HOME", "TMP", "TEMP", "TMPDIR"]);
        assert!(env.iter().all(|(_, v)| v == "C:\\t"));
        let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(env_block(&[(w("A"), w("1")), (w("B"), w("x y"))]), w("A=1\0B=x y\0\0"));
        assert_eq!(env_block(&[]), vec![0, 0]);
        let line = command_line("C:\\Program Files\\Git\\bin\\bash.exe", &["-c".into(), "echo \"hi\" there".into()]);
        // An installed Git Bash is an MSYS2 program: every argument quoted, `-c` included.
        let c = if seagent_core::platform::layout::is_msys_program(Path::new("C:\\Program Files\\Git\\bin\\bash.exe")) { "\"-c\"" } else { "-c" };
        assert_eq!(line, format!("\"C:\\Program Files\\Git\\bin\\bash.exe\" {c} \"echo \\\"hi\\\" there\""));
        let line = command_line("C:\\Windows\\System32\\cmd.exe", &["/c".into(), "a*".into()]);
        assert_eq!(line, "C:\\Windows\\System32\\cmd.exe /c a*");
    }

    #[test]
    fn detached_wrappers_write_the_exit_file() {
        let exit = Path::new("C:\\h\\jobs\\7.exit");
        let (args, env) = detach_wrapper(ShellKind::Bash, Path::new("C:\\Git\\bin\\bash.exe"), "sleep 1; exit 7", true, exit);
        assert_eq!(args[0], "-c");
        assert_eq!(args[2], "C:\\Git\\bin\\bash.exe", "$0 is the shell itself");
        assert!(args[1].contains("\"$0\" \"$o\" \"$c\"") && args[1].contains("> \"$f\""));
        assert!(env.contains(&("SEAGENT_DETACH_SCRIPT".into(), "sleep 1; exit 7".into())) && env.contains(&("SEAGENT_DETACH_FLAG".into(), "-lc".into())));
        assert!(env.contains(&("SEAGENT_EXIT_FILE".into(), exit.display().to_string())));
        let (args, env) = detach_wrapper(ShellKind::WindowsPowerShell, Path::new("powershell.exe"), "exit 3", false, exit);
        assert_eq!(&args[..3], ["-NoProfile", "-NonInteractive", "-Command"]);
        assert!(args[3].contains("-EncodedCommand") && args[3].contains("WriteAllText"));
        let b64 = &env.iter().find(|(k, _)| k == "SEAGENT_DETACH_B64").unwrap().1;
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let utf16: Vec<u16> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16(&utf16).unwrap(), "exit 3", "UTF-16LE base64, as -EncodedCommand wants");
        assert!(env.contains(&("SEAGENT_DETACH_PROFILE".into(), "0".into())));
    }

    #[test]
    fn availability_is_false_off_windows() {
        if !cfg!(windows) {
            assert!(!available());
        }
    }
}
