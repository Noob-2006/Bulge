//! Where seagent keeps its own files: the one place that knows the directory layout.
//!
//! Three modes, decided in this order (first match wins; `seagent config path` prints the result
//! and the reason):
//!
//! 1. **portable** — `$SEAGENT_HOME` is set: everything under it (`config/`, `data/`, `run/`,
//!    `cache/`). Tests, profiles (`seagent -p NAME`) and hand-made portable installs.
//! 2. **explicit** — `$SEAGENT_MODE=system` or `$SEAGENT_MODE=user` (the packaged system unit sets
//!    `SEAGENT_MODE=system`).
//! 3. **system account** — the process runs as a non-root account whose home is
//!    `/var/lib/seagent` (the `seagent` account the packages create): `sudo -u seagent seagent …` therefore
//!    talks to the system instance without extra flags.
//! 4. otherwise **user** (XDG).
//!
//! | | user (XDG) | system (FHS) | portable |
//! |---|---|---|---|
//! | config | `$XDG_CONFIG_HOME/seagent` | `/etc/seagent` | `$SEAGENT_HOME/config` |
//! | data | `$XDG_DATA_HOME/seagent` | `/var/lib/seagent` | `$SEAGENT_HOME/data` |
//! | cache | `$XDG_CACHE_HOME/seagent` | `/var/cache/seagent` | `$SEAGENT_HOME/cache` |
//! | logs | `<data>/logs` | `/var/log/seagent` | `<data>/logs` |
//! | runtime | `$XDG_RUNTIME_DIR/seagent`, else `<data>/run` | `/run/seagent` | `$SEAGENT_HOME/run` |
//! | workspace | `<data>/workspace` | `/var/lib/seagent/workspace` | `<data>/workspace` |
//!
//! Every directory can be overridden on its own: `SEAGENT_CONFIG_DIR`, `SEAGENT_DATA_DIR`,
//! `SEAGENT_CACHE_DIR`, `SEAGENT_LOG_DIR`, `SEAGENT_RUNTIME_DIR` (absolute paths only).
//!
//! Backward compatibility (ent-008): system installs before this layout ran with
//! `SEAGENT_HOME=/var/lib/seagent` (config in `/var/lib/seagent/config`, data in `/var/lib/seagent/data`).
//! A unit that still sets `SEAGENT_HOME` keeps working unchanged (portable mode). In system mode
//! the old locations are still read: `/var/lib/seagent/config` while `/etc/seagent/config.toml` does
//! not exist yet, and `/var/lib/seagent/data` whenever it exists (the package's post-install step
//! copies the old config to `/etc/seagent`; data is never moved).

use std::path::{Path, PathBuf};

/// The FHS layout of the system service, and the directories seagent itself installs to.
pub mod system {
    /// Configuration and administrator policy (`managed.toml`, `managed.d/`).
    pub const CONFIG: &str = "/etc/seagent";
    pub const DATA: &str = "/var/lib/seagent";
    pub const CACHE: &str = "/var/cache/seagent";
    pub const LOGS: &str = "/var/log/seagent";
    pub const RUNTIME: &str = "/run/seagent";
    pub const WORKSPACE: &str = "/var/lib/seagent/workspace";
    /// The dedicated account of the system service (home = [`DATA`]).
    pub const USER: &str = "seagent";
    /// Pre-ent-008 layout (`SEAGENT_HOME=/var/lib/seagent`), still read in system mode.
    pub const LEGACY_CONFIG: &str = "/var/lib/seagent/config";
    pub const LEGACY_DATA: &str = "/var/lib/seagent/data";
    /// Bundled share data of a package / `make install` (searched after the binary-relative ones).
    pub const SHARE: &[&str] = &["/usr/local/share/seagent", "/usr/share/seagent"];
    /// Where the distro packages put the binary.
    pub const BIN: &str = "/usr/bin/seagent";
    /// systemd system units shipped by the packages.
    pub const UNIT_DIR: &str = "/usr/lib/systemd/system";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    User,
    System,
    Portable,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::User => "user",
            Mode::System => "system",
            Mode::Portable => "portable",
        }
    }
}

/// The resolved layout. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub mode: Mode,
    /// Why this mode was chosen (shown by `seagent config path`).
    pub reason: String,
    pub config: PathBuf,
    pub data: PathBuf,
    pub cache: PathBuf,
    pub logs: PathBuf,
    /// As configured; the kernel's `Paths` shortens it when a socket path would be too long.
    pub runtime: PathBuf,
    /// Old locations in use (system mode, pre-ent-008 install): `(what, path)`.
    pub legacy: Vec<(&'static str, PathBuf)>,
}

impl Layout {
    pub fn workspace(&self) -> PathBuf {
        if self.mode == Mode::System {
            return PathBuf::from(system::WORKSPACE);
        }
        self.data.join("workspace")
    }
}

/// What [`detect_with`] may look at (all of it injectable, so the decision is testable).
pub struct Probe<'a> {
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub exists: &'a dyn Fn(&Path) -> bool,
    /// Effective uid and its passwd home directory.
    pub euid: u32,
    pub pw_home: Option<PathBuf>,
}

fn abs(v: Option<String>) -> Option<PathBuf> {
    v.filter(|s| !s.is_empty()).map(PathBuf::from).filter(|p| p.is_absolute())
}

/// `$HOME`, else the passwd entry's home, else the temp dir (never a shared fixed path).
pub fn home_with(p: &Probe) -> PathBuf {
    abs((p.env)("HOME")).or_else(|| p.pw_home.clone()).unwrap_or_else(std::env::temp_dir)
}

/// The user (XDG) layout, ignoring `SEAGENT_HOME` / `SEAGENT_MODE` (profiles live under it).
pub fn user_with(p: &Probe) -> Layout {
    let home = home_with(p);
    let xdg = |var: &str, def: &str| abs((p.env)(var)).unwrap_or_else(|| home.join(def));
    let data = xdg("XDG_DATA_HOME", ".local/share").join("seagent");
    let runtime = abs((p.env)("XDG_RUNTIME_DIR")).map(|r| r.join("seagent")).unwrap_or_else(|| data.join("run"));
    Layout { mode: Mode::User, reason: "default (per-user XDG directories)".into(), config: xdg("XDG_CONFIG_HOME", ".config").join("seagent"), cache: xdg("XDG_CACHE_HOME", ".cache").join("seagent"), logs: data.join("logs"), data, runtime, legacy: vec![] }
}

fn system_with(p: &Probe, reason: String) -> Layout {
    let mut legacy = vec![];
    let mut config = PathBuf::from(system::CONFIG);
    if !(p.exists)(&config.join("config.toml")) && (p.exists)(&Path::new(system::LEGACY_CONFIG).join("config.toml")) {
        config = PathBuf::from(system::LEGACY_CONFIG);
        legacy.push(("config", config.clone()));
    }
    let mut data = PathBuf::from(system::DATA);
    if (p.exists)(Path::new(system::LEGACY_DATA)) {
        data = PathBuf::from(system::LEGACY_DATA);
        legacy.push(("data", data.clone()));
    }
    Layout { mode: Mode::System, reason, config, data, cache: system::CACHE.into(), logs: system::LOGS.into(), runtime: system::RUNTIME.into(), legacy }
}

/// Pure form of [`detect`].
pub fn detect_with(p: &Probe) -> Layout {
    // SEAGENT_HOME may be relative (resolved against the working directory, as it always was):
    // harnesses use `SEAGENT_HOME=h` to keep the socket path short.
    let mut l = if let Some(h) = (p.env)("SEAGENT_HOME").filter(|h| !h.is_empty()).map(PathBuf::from) {
        Layout { mode: Mode::Portable, reason: "SEAGENT_HOME is set".into(), config: h.join("config"), data: h.join("data"), cache: h.join("cache"), logs: h.join("data").join("logs"), runtime: h.join("run"), legacy: vec![] }
    } else {
        match (p.env)("SEAGENT_MODE").map(|m| m.trim().to_ascii_lowercase()).as_deref() {
            Some("system") => system_with(p, "SEAGENT_MODE=system".into()),
            Some("user") => Layout { reason: "SEAGENT_MODE=user".into(), ..user_with(p) },
            _ if p.euid != 0 && p.pw_home.as_deref() == Some(Path::new(system::DATA)) => system_with(p, format!("running as the system account (home {})", system::DATA)),
            _ => user_with(p),
        }
    };
    for (var, slot) in [("SEAGENT_CONFIG_DIR", &mut l.config), ("SEAGENT_DATA_DIR", &mut l.data), ("SEAGENT_CACHE_DIR", &mut l.cache), ("SEAGENT_LOG_DIR", &mut l.logs), ("SEAGENT_RUNTIME_DIR", &mut l.runtime)] {
        if let Some(v) = abs((p.env)(var)) {
            *slot = v;
            l.reason.push_str(&format!("; {var} overrides"));
        }
    }
    l
}

fn real_env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

fn pw_home(uid: u32) -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut out) };
    if rc != 0 || out.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

fn with_probe<T>(f: impl FnOnce(&Probe) -> T) -> T {
    let euid = unsafe { libc::geteuid() };
    let exists = |p: &Path| p.exists();
    f(&Probe { env: &real_env, exists: &exists, euid, pw_home: pw_home(euid) })
}

/// The layout of this process (environment + who we run as).
pub fn detect() -> Layout {
    with_probe(detect_with)
}

/// The per-user XDG layout regardless of `SEAGENT_HOME` / `SEAGENT_MODE`.
pub fn user() -> Layout {
    with_probe(user_with)
}

/// The home directory (`$HOME`, else the passwd entry).
pub fn home() -> PathBuf {
    with_probe(home_with)
}

/// seagent's data dir for crates that have no `Paths` at hand (media models, browser profiles).
pub fn data_dir() -> PathBuf {
    detect().data
}

/// seagent's cache dir (re-downloadable files: models, voices, web cache).
pub fn cache_dir() -> PathBuf {
    detect().cache
}

/// The first executable called `name` on `$PATH` (tool discovery instead of fixed paths).
pub fn which(name: &str) -> Option<PathBuf> {
    which_in(name, std::env::var_os("PATH").as_deref())
}

pub fn which_in(name: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if name.contains('/') {
        return Some(PathBuf::from(name)).filter(|p| p.is_file());
    }
    std::env::split_paths(path?).map(|d| d.join(name)).find(|p| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn run(env: &[(&str, &str)], existing: &[&str], euid: u32, pw: Option<&str>) -> Layout {
        let m: HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let get = move |k: &str| m.get(k).cloned();
        let ex: Vec<PathBuf> = existing.iter().map(PathBuf::from).collect();
        let exists = move |p: &Path| ex.iter().any(|e| e == p);
        detect_with(&Probe { env: &get, exists: &exists, euid, pw_home: pw.map(PathBuf::from) })
    }

    #[test]
    fn user_mode_follows_xdg() {
        let l = run(&[("HOME", "/h/u")], &[], 1000, Some("/h/u"));
        assert_eq!(l.mode, Mode::User);
        assert_eq!((l.config, l.data.clone(), l.cache, l.logs), (PathBuf::from("/h/u/.config/seagent"), PathBuf::from("/h/u/.local/share/seagent"), PathBuf::from("/h/u/.cache/seagent"), PathBuf::from("/h/u/.local/share/seagent/logs")));
        assert_eq!(l.runtime, PathBuf::from("/h/u/.local/share/seagent/run"));
        let l = run(&[("HOME", "/h/u"), ("XDG_CONFIG_HOME", "/c"), ("XDG_DATA_HOME", "/d"), ("XDG_CACHE_HOME", "/k"), ("XDG_RUNTIME_DIR", "/r/1000")], &[], 1000, None);
        assert_eq!((l.config, l.data, l.cache, l.runtime), (PathBuf::from("/c/seagent"), PathBuf::from("/d/seagent"), PathBuf::from("/k/seagent"), PathBuf::from("/r/1000/seagent")));
        // relative XDG values are ignored (the spec says so)
        assert_eq!(run(&[("HOME", "/h"), ("XDG_DATA_HOME", "rel")], &[], 1, None).data, PathBuf::from("/h/.local/share/seagent"));
    }

    #[test]
    fn system_mode_is_explicit_or_the_service_account() {
        let l = run(&[("SEAGENT_MODE", "system"), ("HOME", "/root")], &[], 0, Some("/root"));
        assert_eq!((l.mode, l.config.as_path(), l.data.as_path(), l.cache.as_path(), l.logs.as_path(), l.runtime.as_path()), (Mode::System, Path::new("/etc/seagent"), Path::new("/var/lib/seagent"), Path::new("/var/cache/seagent"), Path::new("/var/log/seagent"), Path::new("/run/seagent")));
        assert_eq!(l.workspace(), PathBuf::from("/var/lib/seagent/workspace"));
        let l = run(&[("HOME", "/var/lib/seagent")], &[], 990, Some("/var/lib/seagent"));
        assert_eq!(l.mode, Mode::System, "{}", l.reason);
        // root whose home happens to be /var/lib/seagent is not the service account
        assert_eq!(run(&[("HOME", "/root")], &[], 0, Some("/var/lib/seagent")).mode, Mode::User);
        assert_eq!(run(&[("SEAGENT_MODE", "user"), ("HOME", "/var/lib/seagent")], &[], 990, Some("/var/lib/seagent")).mode, Mode::User);
    }

    #[test]
    fn pre_ent008_system_installs_keep_their_files() {
        let l = run(&[("SEAGENT_MODE", "system")], &["/var/lib/seagent/config/config.toml", "/var/lib/seagent/data"], 990, None);
        assert_eq!((l.config.as_path(), l.data.as_path()), (Path::new("/var/lib/seagent/config"), Path::new("/var/lib/seagent/data")));
        assert_eq!(l.legacy.len(), 2);
        assert_eq!(l.workspace(), PathBuf::from("/var/lib/seagent/workspace"));
        // once /etc/seagent/config.toml exists (post-install migration), it wins
        let l = run(&[("SEAGENT_MODE", "system")], &["/var/lib/seagent/config/config.toml", "/etc/seagent/config.toml"], 990, None);
        assert_eq!(l.config, PathBuf::from("/etc/seagent"));
        assert!(l.legacy.is_empty());
    }

    #[test]
    fn portable_and_overrides() {
        let l = run(&[("SEAGENT_HOME", "/p"), ("SEAGENT_MODE", "system")], &[], 0, None);
        assert_eq!((l.mode, l.config, l.data, l.cache, l.runtime), (Mode::Portable, PathBuf::from("/p/config"), PathBuf::from("/p/data"), PathBuf::from("/p/cache"), PathBuf::from("/p/run")));
        // a relative SEAGENT_HOME stays relative (harnesses keep socket paths short with `SEAGENT_HOME=h`)
        let l = run(&[("SEAGENT_HOME", "h"), ("HOME", "/real")], &[], 1, None);
        assert_eq!((l.mode, l.data, l.runtime), (Mode::Portable, PathBuf::from("h/data"), PathBuf::from("h/run")));
        let l = run(&[("HOME", "/h"), ("SEAGENT_CACHE_DIR", "/fast/cache"), ("SEAGENT_LOG_DIR", "relative")], &[], 1, None);
        assert_eq!(l.cache, PathBuf::from("/fast/cache"));
        assert_eq!(l.logs, PathBuf::from("/h/.local/share/seagent/logs"), "relative overrides are ignored");
        assert!(l.reason.contains("SEAGENT_CACHE_DIR"));
    }

    #[test]
    fn which_finds_executables_on_path() {
        let t = crate::tmp::TempDir::new("seagent-which");
        let bin = t.path().join("tool");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(t.path().join("plain"), "").unwrap();
        let path = std::env::join_paths([PathBuf::from("/nonexistent"), t.path().to_path_buf()]).unwrap();
        assert_eq!(which_in("tool", Some(&path)), Some(bin));
        assert_eq!(which_in("plain", Some(&path)), None, "not executable");
        assert_eq!(which_in("missing", Some(&path)), None);
    }
}
