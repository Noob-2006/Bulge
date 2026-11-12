//! Shadow-git workspace checkpoints: the safety net that replaces confirmation
//! prompts. Uses a separate git dir, so the user's own repository is untouched.

use std::path::{Path, PathBuf};

pub struct Checkpoints {
    git_dir: PathBuf,
    work: PathBuf,
    limits: Limits,
}

/// Per-snapshot limits (Hermes `checkpoints.max_snapshots` / `max_file_size_mb`). 0 = no limit.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Limits {
    /// Keep at most this many snapshots per workspace (older ones are rewritten away).
    pub max_snapshots: usize,
    /// Do not stage files larger than this many bytes.
    pub max_file_bytes: u64,
}

/// Inside each per-workspace git dir: the workspace path and the last snapshot time.
const WORKDIR_FILE: &str = "seagent-workdir";
const PARENT_ID_FILE: &str = "seagent-parent-id";
const TOUCH_FILE: &str = "seagent-last-touch";
const GC_PENDING: &str = ".gc-pending";

#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub id: String,
    pub time: String,
    pub label: String,
}

const EXCLUDES: &str = ".git/\ntarget/\nnode_modules/\n.venv/\n__pycache__/\n*.o\n.seagent/cache/\n**/browser/profiles/\n**/browser/real-profile/\n**/browser/chrome-debug/\n**/browser/browsers/\nchrome_cdp_profile/\nagent-browser-chrome-*/\n";

/// Canonicalize the nearest existing ancestor and append the rest, so a not-yet-created
/// `<workspace>/.seagent/checkpoints` still compares correctly against the canonical workspace.
fn canonical_best(p: &Path) -> PathBuf {
    let mut cur = p;
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !cur.exists() {
        let (Some(parent), Some(name)) = (cur.parent(), cur.file_name()) else { return p.to_path_buf() };
        rest.push(name.to_os_string());
        cur = parent;
    }
    // `layout::canonicalize` is std on Unix; on Windows it drops `\\?\`, so the result compares
    // with workspace paths spelled the ordinary way.
    let mut out = seagent_core::platform::layout::canonicalize(cur).unwrap_or_else(|_| cur.to_path_buf());
    for name in rest.iter().rev() {
        out.push(name);
    }
    out
}

/// `/`, the home directory and every ancestor of it, and the agent's own browser profiles /
/// checkpoint store: never a project, always huge or recursively self-referential.
fn too_broad(work: &Path, data: &Path, home: Option<&Path>) -> Option<&'static str> {
    if work == Path::new("/") {
        return Some("/");
    }
    // Windows: a drive root is `/`; `\\?\C:\x` and `C:\x` are the same directory.
    #[cfg(windows)]
    let work_owned = seagent_core::platform::layout::simplify_verbatim(work);
    #[cfg(windows)]
    let work = work_owned.as_path();
    #[cfg(windows)]
    if work.parent().is_none() {
        return Some("/");
    }
    if let Some(home) = home {
        let home = canonical_best(home);
        if home == work || home.starts_with(work) {
            return Some("the home directory or one of its parents");
        }
    }
    let browser = canonical_best(&data.join("browser"));
    if work == browser || work.starts_with(&browser) {
        return Some("a browser profile directory");
    }
    let store = canonical_best(&data.join("checkpoints"));
    if work == store || work.starts_with(&store) {
        return Some("the checkpoint store");
    }
    None
}

impl Checkpoints {
    pub fn new(data: &Path, workspace: &Path) -> Result<Self, String> {
        // `layout::canonicalize`: std on Unix, no `\\?\` on Windows (git and `canonical_best` agree).
        let work = seagent_core::platform::layout::canonicalize(workspace).map_err(|e| format!("{}: {e}", workspace.display()))?;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if let Some(why) = too_broad(&work, data, home.as_deref()) {
            return Err(format!("refusing to checkpoint {why}; run seagent inside a project folder"));
        }
        let key: u64 = work.to_string_lossy().bytes().fold(0xcbf29ce484222325, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        Ok(Checkpoints { git_dir: data.join("checkpoints").join(format!("{key:016x}")), work, limits: Limits::default() })
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    fn git(&self, args: &[&str]) -> Result<String, String> {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        self.git_args(&owned)
    }

    fn git_args(&self, args: &[String]) -> Result<String, String> {
        let out = seagent_core::platform::proc::command("git")
            .arg("--git-dir")
            .arg(&self.git_dir)
            .arg("--work-tree")
            .arg(&self.work)
            .args(["-c", "user.name=seagent", "-c", "user.email=seagent@localhost", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("git not available: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn init(&self) -> Result<(), String> {
        if self.git_dir.join("HEAD").exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.git_dir).map_err(|e| e.to_string())?;
        self.git(&["init", "-q"])?;
        std::fs::create_dir_all(self.git_dir.join("info")).map_err(|e| e.to_string())?;
        std::fs::write(self.git_dir.join("info/exclude"), EXCLUDES).map_err(|e| e.to_string())
    }

    /// Record where this store's workspace lives (orphan detection) and when it was used.
    fn touch(&self) {
        let _ = std::fs::write(self.git_dir.join(WORKDIR_FILE), self.work.to_string_lossy().as_bytes());
        if let Some(id) = self.work.parent().and_then(dir_identity) {
            let _ = std::fs::write(self.git_dir.join(PARENT_ID_FILE), format!("{} {}", id.0, id.1));
        }
        let _ = std::fs::write(self.git_dir.join(TOUCH_FILE), crate::util::unix_now().to_string());
    }

    /// The store can sit inside the workspace (a portable `SEAGENT_HOME`). Snapshotting it
    /// would stage every previous packfile into the next snapshot, so it is excluded at any
    /// depth and never restored over.
    fn store_rel(&self) -> Option<String> {
        let base = canonical_best(self.git_dir.parent().unwrap_or(&self.git_dir));
        base.strip_prefix(&self.work).ok().filter(|p| !p.as_os_str().is_empty()).map(|p| p.to_string_lossy().replace('\\', "/"))
    }

    fn store_pathspec(&self) -> Option<String> {
        self.store_rel().map(|r| format!(":(exclude,literal){r}"))
    }

    /// Drop ignored paths that an older index still tracks (git only applies `info/exclude`
    /// to paths it is not already tracking). This is what makes the file count and size cap
    /// ignore excluded paths instead of treating them as workspace content.
    fn unstage_excluded(&self) -> Result<(), String> {
        let exclude = self.git_dir.join("info/exclude");
        if !exclude.exists() {
            return Ok(());
        }
        let names = self.git_args(&["ls-files".into(), "--cached".into(), "--ignored".into(), "-z".into(), format!("--exclude-from={}", exclude.display())])?;
        let paths: Vec<String> = names.split('\0').filter(|n| !n.is_empty()).map(String::from).collect();
        for chunk in paths.chunks(200) {
            let mut args = vec!["rm".into(), "-r".into(), "-q".into(), "--cached".into(), "--ignore-unmatch".into(), "--".into()];
            args.extend(chunk.iter().cloned());
            self.git_args(&args)?;
        }
        Ok(())
    }

    /// Drop a store captured by a snapshot taken before it was excluded.
    fn unstage_store(&self) -> Result<(), String> {
        let Some(rel) = self.store_rel() else { return Ok(()) };
        self.git_args(&["rm".into(), "-r".into(), "-q".into(), "--cached".into(), "--ignore-unmatch".into(), "--".into(), format!(":(literal){rel}")])?;
        Ok(())
    }

    /// Unstage newly added/modified files over the size limit (datasets, model weights).
    fn drop_large(&self) -> Result<(), String> {
        if self.limits.max_file_bytes == 0 {
            return Ok(());
        }
        let names = self.git(&["diff", "--cached", "--name-only", "-z", "--diff-filter=AM"])?;
        for name in names.split('\0').filter(|n| !n.is_empty()) {
            let big = std::fs::metadata(self.work.join(name)).map(|m| m.len() > self.limits.max_file_bytes).unwrap_or(false);
            if big {
                self.git(&["rm", "--cached", "-q", "--", name])?;
            }
        }
        Ok(())
    }

    fn head_ref(&self) -> Result<String, String> {
        Ok(self.git(&["symbolic-ref", "-q", "HEAD"]).unwrap_or_else(|_| "HEAD".into()).trim().to_string())
    }

    /// Number of snapshots.
    pub fn count(&self) -> usize {
        self.git(&["rev-list", "--count", "HEAD"]).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
    }

    /// Keep only the newest `keep` snapshots (Hermes `Pruner.trim`): history is
    /// rewritten with the same trees, messages and dates; the gc is deferred.
    pub fn trim(&self, keep: usize) -> Result<bool, String> {
        let commits: Vec<String> = self.git(&["rev-list", "--reverse", "HEAD"])?.lines().map(String::from).collect();
        let keep = keep.max(1);
        if commits.len() <= keep {
            return Ok(false);
        }
        self.rewrite(&commits, &commits[commits.len() - keep..], false)?;
        Ok(true)
    }

    fn rewrite(&self, original: &[String], keep: &[String], gc: bool) -> Result<(), String> {
        let mut parent: Option<String> = None;
        for sha in keep {
            let meta = self.git(&["log", "-1", "--format=%T%x00%aI%x00%cI%x00%s", sha])?;
            let f: Vec<&str> = meta.trim_end_matches('\n').splitn(4, '\0').collect();
            if f.len() != 4 {
                return Err(format!("invalid checkpoint metadata: {sha}"));
            }
            let mut args = vec!["commit-tree", f[0], "-m", f[3]];
            if let Some(p) = &parent {
                args.extend(["-p", p.as_str()]);
            }
            let out = seagent_core::platform::proc::command("git")
                .arg("--git-dir")
                .arg(&self.git_dir)
                .args(["-c", "user.name=seagent", "-c", "user.email=seagent@localhost", "-c", "commit.gpgsign=false"])
                .args(&args)
                .env("GIT_AUTHOR_DATE", f[1])
                .env("GIT_COMMITTER_DATE", f[2])
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|e| format!("git not available: {e}"))?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
            }
            parent = Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
        let Some(new_head) = parent else { return Err("cannot remove a workspace's last snapshot".into()) };
        let r = self.head_ref()?;
        // Never overwrite a snapshot published since we read this history.
        self.git(&["update-ref", &r, &new_head, original.last().map(String::as_str).unwrap_or("")])?;
        if gc {
            self.reclaim()
        } else {
            let _ = std::fs::write(self.git_dir.join(GC_PENDING), b"");
            Ok(())
        }
    }

    /// Drop the oldest snapshot (keeps at least one). Returns whether one was dropped.
    fn drop_oldest(&self, gc: bool) -> Result<bool, String> {
        let commits: Vec<String> = self.git(&["rev-list", "--reverse", "HEAD"])?.lines().map(String::from).collect();
        if commits.len() <= 1 {
            return Ok(false);
        }
        self.rewrite(&commits, &commits[1..], gc)?;
        Ok(true)
    }

    /// Full gc: expire the reflog and prune unreachable objects.
    pub fn reclaim(&self) -> Result<(), String> {
        self.git(&["reflog", "expire", "--expire=now", "--all"])?;
        self.git(&["gc", "--prune=now", "--quiet"])?;
        let _ = std::fs::remove_file(self.git_dir.join(GC_PENDING));
        Ok(())
    }

    /// Snapshot the workspace. Returns None when nothing changed since the last one.
    pub fn snapshot(&self, label: &str, max_files: usize) -> Result<Option<String>, String> {
        let _lock = StoreLock::shared(self.git_dir.parent().unwrap_or(&self.git_dir))?;
        self.init()?;
        self.touch();
        self.unstage_excluded()?;
        self.unstage_store()?;
        let mut add = vec!["add".into(), "-A".into(), "--".into(), ".".into()];
        if let Some(p) = self.store_pathspec() {
            add.push(p);
        }
        self.git_args(&add)?;
        self.unstage_excluded()?;
        self.drop_large()?;
        let n = self.git(&["ls-files", "--cached"])?.lines().count();
        if n > max_files {
            self.git(&["reset", "-q"]).ok();
            return Err(format!("workspace has {n} files (> {max_files}); checkpoint skipped"));
        }
        let has_head = self.git(&["rev-parse", "--verify", "-q", "HEAD"]).is_ok();
        if has_head && self.git(&["diff", "--cached", "--quiet"]).is_ok() {
            return Ok(None);
        }
        self.git(&["commit", "-q", "--allow-empty", "-m", label])?;
        let id = self.git(&["rev-parse", "--short", "HEAD"])?.trim().to_string();
        if self.limits.max_snapshots > 0 {
            // A rewrite gives every kept snapshot a new id; report the newest one's.
            if self.trim(self.limits.max_snapshots)? {
                return Ok(Some(self.git(&["rev-parse", "--short", "HEAD"])?.trim().to_string()));
            }
        }
        Ok(Some(id))
    }

    pub fn list(&self, limit: usize) -> Result<Vec<Checkpoint>, String> {
        if !self.git_dir.join("HEAD").exists() {
            return Ok(vec![]);
        }
        let out = match self.git(&["log", &format!("-{limit}"), "--format=%h\t%ci\t%s"]) {
            Ok(o) => o,
            Err(e) if e.contains("does not have any commits") => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        Ok(out
            .lines()
            .filter_map(|l| {
                let mut p = l.splitn(3, '\t');
                Some(Checkpoint { id: p.next()?.into(), time: p.next()?.into(), label: p.next().unwrap_or("").into() })
            })
            .collect())
    }

    /// Paths whose working-tree state differs from checkpoint `id`: modified and
    /// deleted tracked files plus new untracked ones (`/undo`'s changed-files line).
    /// Read-only: it writes no object, ref or index.
    pub fn changed_files(&self, id: &str) -> Result<Vec<String>, String> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("bad checkpoint id `{id}`"));
        }
        self.git(&["rev-parse", "--verify", "-q", &format!("{id}^{{commit}}")]).map_err(|_| format!("no checkpoint {id}"))?;
        let tracked = self.git(&["diff", "--name-only", "-z", id, "--"])?;
        let untracked = self.git(&["ls-files", "--others", "--exclude-standard", "-z"])?;
        let mut out: Vec<String> = tracked.split('\0').chain(untracked.split('\0')).filter(|p| !p.is_empty()).map(str::to_string).collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Restore the workspace to a checkpoint. The current state is snapshotted
    /// first, so a restore is itself undoable.
    pub fn restore(&self, id: &str) -> Result<Option<String>, String> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("bad checkpoint id `{id}`"));
        }
        self.git(&["rev-parse", "--verify", "-q", &format!("{id}^{{commit}}")]).map_err(|_| format!("no checkpoint {id}"))?;
        let before = self.snapshot(&format!("before restore to {id}"), usize::MAX)?;
        // `restore` (unlike `read-tree`) takes a pathspec, so the checkpoint store is never
        // rewound by rolling the workspace back over it.
        let mut args = vec!["restore".into(), format!("--source={id}"), "--worktree".into(), "--staged".into(), "--".into(), ".".into()];
        if let Some(p) = self.store_pathspec() {
            args.push(p);
        }
        self.git_args(&args)?;
        Ok(before)
    }
}

// ───────────────────────── store maintenance ─────────────────────────

/// `flock` on `<base>/.lock`: snapshots share it, prune/clear take it exclusively.
struct StoreLock {
    _file: std::fs::File,
}

impl StoreLock {
    fn open(base: &Path) -> Result<std::fs::File, String> {
        std::fs::create_dir_all(base).map_err(|e| e.to_string())?;
        std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(base.join(".lock")).map_err(|e| e.to_string())
    }
    fn shared(base: &Path) -> Result<StoreLock, String> {
        let f = Self::open(base)?;
        // flock(LOCK_SH) on Unix (LockFileEx on Windows); released when the file closes.
        // Best effort, as before: a failed lock does not stop the snapshot.
        let _ = f.lock_shared();
        Ok(StoreLock { _file: f })
    }
    fn exclusive(base: &Path) -> Result<StoreLock, String> {
        let f = Self::open(base)?;
        // flock(LOCK_EX | LOCK_NB) on Unix.
        if f.try_lock().is_err() {
            return Err(format!("checkpoint store is busy: {}", base.display()));
        }
        Ok(StoreLock { _file: f })
    }
}

#[cfg(unix)]
fn dir_identity(p: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
}

/// Windows: volume serial number + file index (the NTFS equivalent of device + inode),
/// read through `GetFileInformationByHandle` on a directory handle.
#[cfg(windows)]
fn dir_identity(p: &Path) -> Option<(u64, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS};
    // FILE_FLAG_BACKUP_SEMANTICS is what lets CreateFileW open a directory.
    let f = std::fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(p).ok()?;
    // SAFETY: zeroed POD out-parameter; valid handle owned by `f`.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut info) } == 0 {
        return None;
    }
    Some((info.dwVolumeSerialNumber as u64, ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64))
}

#[cfg(not(any(unix, windows)))]
fn dir_identity(_p: &Path) -> Option<(u64, u64)> {
    None
}

pub fn dir_size(p: &Path) -> u64 {
    let Ok(m) = std::fs::symlink_metadata(p) else { return 0 };
    if !m.is_dir() {
        return m.len();
    }
    std::fs::read_dir(p).map(|rd| rd.flatten().map(|e| dir_size(&e.path())).sum()).unwrap_or(0)
}

/// True only when the workspace was observably deleted (Hermes
/// `_workdir_is_observably_gone`): its parent exists, is the same directory it
/// was (device + inode recorded while the workspace was live), and is either
/// non-empty or a live mount point. An unplugged drive or downed share never
/// looks deleted, so its restore points survive.
pub fn workdir_gone(workdir: &Path, parent_id: Option<(u64, u64)>) -> bool {
    if workdir.as_os_str().is_empty() || workdir.exists() {
        return false;
    }
    let Some(parent) = workdir.parent().filter(|p| *p != workdir) else { return false };
    if !parent.is_dir() {
        return false;
    }
    match (parent_id, dir_identity(parent)) {
        (Some(want), Some(have)) if want == have => {}
        _ => return false,
    }
    if std::fs::read_dir(parent).map(|mut r| r.next().is_some()).unwrap_or(false) {
        return true;
    }
    // Empty parent: evidence only if it is a mount point (device differs from its parent's).
    match (dir_identity(parent), parent.parent().and_then(dir_identity)) {
        (Some(a), Some(b)) => a.0 != b.0,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectStatus {
    pub id: String,
    /// Empty when the store predates workspace tracking.
    pub workdir: String,
    pub exists: bool,
    pub snapshots: usize,
    pub size_bytes: u64,
    /// Unix seconds; 0 = unknown.
    pub last_touch: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct StoreStatus {
    pub base: PathBuf,
    pub total_size_bytes: u64,
    pub projects: Vec<ProjectStatus>,
}

/// Counts from a prune, as upstream reports them.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PruneResult {
    pub scanned: usize,
    pub deleted_orphan: usize,
    pub deleted_stale: usize,
    pub errors: usize,
    pub bytes_freed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PruneOpts {
    /// Delete workspaces untouched for this many days (0 = never).
    pub retention_days: u32,
    /// Delete stores whose workspace was observably deleted.
    pub delete_orphans: bool,
    /// After that, drop oldest snapshots round-robin until the store fits (0 = no cap).
    pub max_total_bytes: u64,
}

/// The whole shadow store (`<data>/checkpoints`).
pub struct Store {
    pub base: PathBuf,
}

const PRUNE_MARKER: &str = ".last_prune";

impl Store {
    pub fn new(data: &Path) -> Store {
        Store { base: data.join("checkpoints") }
    }

    fn projects(&self) -> Vec<(String, PathBuf)> {
        let Ok(rd) = std::fs::read_dir(&self.base) else { return vec![] };
        let mut v: Vec<(String, PathBuf)> = rd.flatten().filter(|e| e.path().join("HEAD").is_file()).map(|e| (e.file_name().to_string_lossy().to_string(), e.path())).collect();
        v.sort();
        v
    }

    fn handle(dir: &Path) -> Checkpoints {
        let work = std::fs::read_to_string(dir.join(WORKDIR_FILE)).map(PathBuf::from).unwrap_or_default();
        Checkpoints { git_dir: dir.to_path_buf(), work, limits: Limits::default() }
    }

    fn last_touch(dir: &Path) -> i64 {
        if let Some(t) = std::fs::read_to_string(dir.join(TOUCH_FILE)).ok().and_then(|s| s.trim().parse().ok()) {
            return t;
        }
        // Stores from before touch tracking: the newest of HEAD / index / logs.
        ["HEAD", "index", "logs/HEAD"]
            .iter()
            .filter_map(|f| std::fs::metadata(dir.join(f)).ok()?.modified().ok())
            .max()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn parent_id(dir: &Path) -> Option<(u64, u64)> {
        let s = std::fs::read_to_string(dir.join(PARENT_ID_FILE)).ok()?;
        let (a, b) = s.trim().split_once(' ')?;
        Some((a.parse().ok()?, b.parse().ok()?))
    }

    pub fn status(&self) -> StoreStatus {
        let projects = self
            .projects()
            .into_iter()
            .map(|(id, dir)| {
                let h = Self::handle(&dir);
                ProjectStatus { id, workdir: h.work.to_string_lossy().to_string(), exists: !h.work.as_os_str().is_empty() && h.work.exists(), snapshots: h.count(), size_bytes: dir_size(&dir), last_touch: Self::last_touch(&dir) }
            })
            .collect();
        StoreStatus { base: self.base.clone(), total_size_bytes: dir_size(&self.base), projects }
    }

    /// Delete orphan/stale stores, reclaim deferred gcs, then enforce the size cap
    /// (Hermes `prune_checkpoints`). Never panics; failures are counted.
    pub fn prune(&self, o: PruneOpts) -> PruneResult {
        let mut r = PruneResult::default();
        if !self.base.exists() {
            return r;
        }
        let _lock = match StoreLock::exclusive(&self.base) {
            Ok(l) => l,
            Err(_) => {
                r.errors += 1;
                return r;
            }
        };
        let now = crate::util::unix_now();
        let cutoff = (o.retention_days > 0).then(|| now - o.retention_days as i64 * 86_400);
        let mut alive = Vec::new();
        for (_, dir) in self.projects() {
            r.scanned += 1;
            let h = Self::handle(&dir);
            let orphan = o.delete_orphans && workdir_gone(&h.work, Self::parent_id(&dir));
            let stale = cutoff.is_some_and(|c| Self::last_touch(&dir) < c);
            if orphan || stale {
                let size = dir_size(&dir);
                match std::fs::remove_dir_all(&dir) {
                    Ok(()) => {
                        r.bytes_freed += size;
                        if orphan {
                            r.deleted_orphan += 1;
                        } else {
                            r.deleted_stale += 1;
                        }
                    }
                    Err(_) => r.errors += 1,
                }
                continue;
            }
            if dir.join(GC_PENDING).exists() {
                let before = dir_size(&dir);
                if h.reclaim().is_err() {
                    r.errors += 1;
                }
                r.bytes_freed += before.saturating_sub(dir_size(&dir));
            }
            alive.push(h);
        }
        if o.max_total_bytes > 0 && dir_size(&self.base) > o.max_total_bytes {
            // Round-robin, remeasuring after each rewrite; twenty rounds bound the work.
            'rounds: for _ in 0..20 {
                let mut changed = false;
                for h in &alive {
                    let before = dir_size(&h.git_dir);
                    match h.drop_oldest(true) {
                        Ok(true) => {
                            changed = true;
                            r.bytes_freed += before.saturating_sub(dir_size(&h.git_dir));
                        }
                        Ok(false) => {}
                        Err(_) => r.errors += 1,
                    }
                    if dir_size(&self.base) <= o.max_total_bytes {
                        break 'rounds;
                    }
                }
                if !changed {
                    break;
                }
            }
        }
        r
    }

    /// `prune` at most once per `min_interval_hours` (marker `.last_prune`), never
    /// deleting orphans unattended (a missing workspace may be an unmounted volume).
    pub fn maybe_auto_prune(&self, retention_days: u32, min_interval_hours: u32, max_total_bytes: u64) -> Option<PruneResult> {
        if !self.base.exists() {
            return None;
        }
        let marker = self.base.join(PRUNE_MARKER);
        let now = crate::util::unix_now();
        if let Some(last) = std::fs::read_to_string(&marker).ok().and_then(|s| s.trim().parse::<f64>().ok()) {
            if (now as f64 - last) < min_interval_hours as f64 * 3600.0 {
                return None;
            }
        }
        // Claim the interval first: a prune that dies costs one skipped interval, not a gc every tick.
        let _ = std::fs::write(&marker, now.to_string());
        Some(self.prune(PruneOpts { retention_days, delete_orphans: false, max_total_bytes }))
    }

    /// Delete every checkpoint (irreversible). Returns bytes freed.
    pub fn clear(&self) -> Result<u64, String> {
        if !self.base.exists() {
            return Ok(0);
        }
        let _lock = StoreLock::exclusive(&self.base)?;
        let size = dir_size(&self.base);
        for (_, dir) in self.projects() {
            std::fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let _ = std::fs::remove_file(self.base.join(PRUNE_MARKER));
        Ok(size.saturating_sub(dir_size(&self.base)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Data dir + workspace on a self-removing temp dir. Callers bind the guard too, e.g.
    /// `let (_dir, data, ws) = setup();`, so the `seagent-ckpt-*` tree no longer survives the test.
    fn setup() -> (seagent_core::tmp::TempDir, PathBuf, PathBuf) {
        let root = seagent_core::tmp::TempDir::new("seagent-ckpt");
        let ws = root.path().join("ws");
        fs::create_dir_all(ws.join("src")).unwrap();
        let data = root.path().join("data");
        (root, data, ws)
    }

    #[test]
    fn snapshot_restore_roundtrip_including_new_and_deleted_files() {
        let (_dir, data, ws) = setup();
        let c = Checkpoints::new(&data, &ws).unwrap();
        fs::write(ws.join("src/a.txt"), "v1").unwrap();
        fs::write(ws.join("keep.txt"), "k").unwrap();
        let first = c.snapshot("turn 1", 1000).unwrap().unwrap();
        assert_eq!(c.snapshot("again", 1000).unwrap(), None, "no change, no commit");
        fs::write(ws.join("src/a.txt"), "v2").unwrap();
        fs::write(ws.join("new.txt"), "n").unwrap();
        fs::remove_file(ws.join("keep.txt")).unwrap();
        let undo = c.restore(&first).unwrap();
        assert!(undo.is_some(), "state before restore was saved");
        assert_eq!(fs::read_to_string(ws.join("src/a.txt")).unwrap(), "v1");
        assert!(ws.join("keep.txt").exists());
        assert!(!ws.join("new.txt").exists());
        // Undo the restore.
        c.restore(&undo.unwrap()).unwrap();
        assert_eq!(fs::read_to_string(ws.join("src/a.txt")).unwrap(), "v2");
        assert!(c.list(10).unwrap().len() >= 3);
    }

    #[test]
    fn user_repo_untouched_and_excludes_respected() {
        let (_dir, data, ws) = setup();
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::create_dir_all(ws.join("target")).unwrap();
        fs::write(ws.join("target/big"), "x").unwrap();
        fs::write(ws.join("a"), "1").unwrap();
        let c = Checkpoints::new(&data, &ws).unwrap();
        c.snapshot("t", 1000).unwrap();
        let files = c.git(&["ls-files"]).unwrap();
        assert_eq!(files.trim(), "a");
        assert_eq!(fs::read_to_string(ws.join(".git/HEAD")).unwrap(), "ref: refs/heads/main\n");
    }

    #[test]
    fn changed_files_lists_tracked_edits_deletions_and_new_files() {
        let (_dir, data, ws) = setup();
        let c = Checkpoints::new(&data, &ws).unwrap();
        fs::write(ws.join("src/a.txt"), "v1").unwrap();
        fs::write(ws.join("keep.txt"), "k").unwrap();
        fs::write(ws.join("gone.txt"), "g").unwrap();
        let first = c.snapshot("turn 1", 1000).unwrap().unwrap();
        assert!(c.changed_files(&first).unwrap().is_empty(), "nothing changed yet");
        fs::write(ws.join("src/a.txt"), "v2").unwrap();
        fs::write(ws.join("new.txt"), "n").unwrap();
        fs::remove_file(ws.join("gone.txt")).unwrap();
        assert_eq!(c.changed_files(&first).unwrap(), ["gone.txt", "new.txt", "src/a.txt"]);
        // Untracked files are listed too; ignored files are not.
        fs::create_dir_all(ws.join("target")).unwrap();
        fs::write(ws.join("target/ignored"), "x").unwrap();
        assert!(!c.changed_files(&first).unwrap().iter().any(|p| p.contains("ignored")));
        assert!(c.changed_files("deadbeef").unwrap_err().contains("no checkpoint"));
        assert!(c.changed_files("zzz").unwrap_err().contains("bad checkpoint"));
    }

    #[test]
    fn failure_paths() {
        let (_dir, data, ws) = setup();
        let c = Checkpoints::new(&data, &ws).unwrap();
        assert!(c.list(5).unwrap().is_empty());
        assert!(c.restore("zzz").unwrap_err().contains("bad checkpoint"));
        assert!(c.restore("").is_err());
        fs::write(ws.join("a"), "1").unwrap();
        c.snapshot("t", 1000).unwrap();
        assert!(c.restore("deadbeef").unwrap_err().contains("no checkpoint"));
        fs::write(ws.join("b"), "1").unwrap();
        assert!(c.snapshot("t", 1).unwrap_err().contains("skipped"));
        assert!(Checkpoints::new(&data, Path::new("/")).is_err());
        assert!(Checkpoints::new(&data, Path::new("/nonexistent/ws")).is_err());
    }

    #[test]
    fn snapshot_limits_trim_history_and_skip_large_files() {
        let (_dir, data, ws) = setup();
        let c = Checkpoints::new(&data, &ws).unwrap().with_limits(Limits { max_snapshots: 2, max_file_bytes: 10 });
        for i in 0..4 {
            fs::write(ws.join("a.txt"), format!("v{i}")).unwrap();
            c.snapshot(&format!("turn {i}"), 1000).unwrap();
        }
        assert_eq!(c.count(), 2, "only the newest two kept");
        let labels: Vec<_> = c.list(10).unwrap().into_iter().map(|x| x.label).collect();
        assert_eq!(labels, ["turn 3", "turn 2"]);
        assert!(c.git_dir().join(GC_PENDING).exists(), "gc deferred to the next prune");
        fs::write(ws.join("big.bin"), "x".repeat(100)).unwrap();
        fs::write(ws.join("a.txt"), "v9").unwrap();
        c.snapshot("t", 1000).unwrap();
        assert!(!c.git(&["ls-files"]).unwrap().contains("big.bin"));
        assert!(ws.join("big.bin").exists(), "the file itself is untouched");
        assert_eq!(fs::read_to_string(c.git_dir().join(WORKDIR_FILE)).unwrap(), seagent_core::platform::layout::canonicalize(&ws).unwrap().to_string_lossy());
    }

    #[test]
    fn prune_removes_orphans_stale_and_enforces_size() {
        // Guard: `seagent-ckpt-prune-*` used to be left in the temp dir after every run.
        let root = seagent_core::tmp::TempDir::new("seagent-ckpt-prune");
        let data = root.join("data");
        let mk = |name: &str| {
            let ws = root.join("projects").join(name);
            fs::create_dir_all(&ws).unwrap();
            fs::write(ws.join("f"), name).unwrap();
            let c = Checkpoints::new(&data, &ws).unwrap();
            c.snapshot("t", 100).unwrap();
            (ws, c)
        };
        let (gone_ws, _) = mk("gone");
        let (_, old) = mk("old");
        let (keep_ws, keep) = mk("keep");
        for i in 0..5 {
            fs::write(keep_ws.join("f"), "y".repeat(2000 * (i + 1))).unwrap();
            keep.snapshot("more", 100).unwrap();
        }
        fs::remove_dir_all(&gone_ws).unwrap();
        fs::write(old.git_dir().join(TOUCH_FILE), "1000").unwrap();
        let store = Store::new(&data);
        let st = store.status();
        assert_eq!(st.projects.len(), 3);
        assert!(st.projects.iter().any(|p| !p.exists && p.workdir.ends_with("gone")));
        // Unattended: orphans are never deleted; stale ones are.
        let r = store.maybe_auto_prune(7, 24, 0).unwrap();
        assert_eq!((r.deleted_orphan, r.deleted_stale), (0, 1));
        assert!(store.maybe_auto_prune(7, 24, 0).is_none(), "interval marker");
        let r = store.prune(PruneOpts { retention_days: 0, delete_orphans: true, max_total_bytes: 0 });
        assert_eq!(r.deleted_orphan, 1, "{r:?}");
        assert_eq!(store.status().projects.len(), 1);
        let before = keep.count();
        let r = store.prune(PruneOpts { retention_days: 0, delete_orphans: true, max_total_bytes: 1 });
        assert_eq!(r.errors, 0);
        assert!(keep.count() < before && keep.count() >= 1, "oldest dropped, one always kept");
        assert!(store.clear().unwrap() > 0);
        assert!(store.status().projects.is_empty());
    }

    #[test]
    fn refuses_home_parents_browser_profiles_and_the_store_itself() {
        let root = seagent_core::tmp::TempDir::new("seagent-broad");
        let home = root.join("home");
        let data = root.join("data");
        fs::create_dir_all(home.join("project")).unwrap();
        fs::create_dir_all(data.join("browser/profiles/work")).unwrap();
        let home = home.canonicalize().unwrap();
        let ws = home.join("project");
        assert_eq!(too_broad(&home, &data, Some(&home)), Some("the home directory or one of its parents"), "the home directory itself");
        assert!(too_broad(home.parent().unwrap(), &data, Some(&home)).is_some(), "a parent of home");
        assert_eq!(too_broad(&ws, &data, Some(&home)), None, "a normal project under home is fine");
        let profile = data.join("browser/profiles/work");
        assert_eq!(too_broad(&profile, &data, None), Some("a browser profile directory"));
        assert_eq!(too_broad(&data.join("browser"), &data, None), Some("a browser profile directory"));
        assert_eq!(too_broad(&data.join("checkpoints"), &data, None), Some("the checkpoint store"));
        assert_eq!(too_broad(&data.join("checkpoints/abc"), &data, None), Some("the checkpoint store"));
        assert_eq!(too_broad(&data.join("workspace"), &data, None), None);
        assert!(Checkpoints::new(&data, &profile).err().unwrap().contains("browser profile"));
    }

    #[test]
    fn store_inside_workspace_is_never_staged_or_rewound() {
        let root = seagent_core::tmp::TempDir::new("seagent-selfstore");
        let ws = root.join("ws");
        let data = ws.join(".seagent");
        fs::create_dir_all(&data).unwrap();
        fs::write(ws.join("a.txt"), "v1").unwrap();
        let c = Checkpoints::new(&data, &ws).unwrap();
        c.snapshot("first", 1000).unwrap();
        assert!(!c.git(&["ls-files"]).unwrap().contains(".seagent"), "the store is not workspace content");
        // A snapshot from before the exclusion still carries the store in its tree.
        fs::write(c.git_dir().join("legacy-marker"), "old").unwrap();
        c.git(&["add", "-A", "."]).unwrap();
        c.git(&["commit", "-q", "--allow-empty", "-m", "legacy store snapshot"]).unwrap();
        let legacy = c.git(&["rev-parse", "HEAD"]).unwrap().trim().to_string();
        fs::write(c.git_dir().join("legacy-marker"), "new").unwrap();
        fs::write(ws.join("a.txt"), "v2").unwrap();
        c.restore(&legacy).unwrap();
        assert_eq!(fs::read_to_string(c.git_dir().join("legacy-marker")).unwrap(), "new", "rollback must not rewind the store");
        assert_eq!(fs::read_to_string(ws.join("a.txt")).unwrap(), "v1", "the workspace itself rolled back");
        assert!(c.git_dir().join("HEAD").exists());
        assert!(c.snapshot("after", 1000).is_ok(), "the store still works");
    }

    #[test]
    fn size_and_file_caps_ignore_excluded_paths_already_in_the_index() {
        let (_dir, data, ws) = setup();
        fs::write(ws.join("a.txt"), "1").unwrap();
        let c = Checkpoints::new(&data, &ws).unwrap().with_limits(Limits { max_snapshots: 0, max_file_bytes: 10 });
        c.snapshot("first", 1000).unwrap();
        // An older index may track an excluded path; it must be dropped before counting,
        // not treated as a 2nd workspace file or stat'ed against the size cap.
        fs::create_dir_all(ws.join("target")).unwrap();
        fs::write(ws.join("target/big.bin"), "x".repeat(100)).unwrap();
        c.git(&["add", "-A", "."]).unwrap();
        c.snapshot("cap", 1).unwrap();
        let files = c.git(&["ls-files"]).unwrap();
        assert_eq!(files.trim(), "a.txt");
        assert!(ws.join("target/big.bin").exists(), "the file itself is untouched");
    }

    #[test]
    fn missing_parent_or_unrecorded_identity_is_not_an_orphan() {
        // Guard: `seagent-orphan-*` used to be left in the temp dir after every run.
        let root = seagent_core::tmp::TempDir::new("seagent-orphan");
        fs::create_dir_all(root.join("p/other")).unwrap();
        let id = dir_identity(&root.join("p"));
        assert!(workdir_gone(&root.join("p/proj"), id));
        assert!(!workdir_gone(&root.join("p/proj"), None), "no recorded identity: unsure never deletes");
        assert!(!workdir_gone(&root.join("absent/proj"), id), "parent missing: volume not there");
        assert!(!workdir_gone(&root.join("p/other"), id), "still exists");
        fs::remove_dir_all(root.join("p/other")).unwrap();
        assert!(!workdir_gone(&root.join("p/proj"), id), "empty plain dir looks like an unmounted mount point");
    }
}
