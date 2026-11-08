//! Per-OS default directories and executable lookup, used by `crate::layout` (which stays the
//! one definition of seagent's layout and keeps its Linux XDG / FHS rules unchanged).
//!
//! | OS | config | data | cache | logs | runtime |
//! |---|---|---|---|---|---|
//! | Linux / other Unix | XDG (see `crate::layout`) | | | | |
//! | macOS | `~/Library/Application Support/seagent/config` | `…/seagent/data` | `~/Library/Caches/seagent` | `~/Library/Logs/seagent` | `…/seagent/run` |
//! | Windows (user) | `%APPDATA%\seagent` | `%LOCALAPPDATA%\seagent\data` | `%LOCALAPPDATA%\seagent\cache` | `<data>\logs` | `%LOCALAPPDATA%\seagent\run` |
//! | Windows (system) | `%ProgramData%\seagent\config` | `…\data` | `…\cache` | `…\logs` | `…\run` |
//! | Android / iOS | `<home>/seagent/config` | `<home>/seagent/data` | `<home>/seagent/cache` | `<data>/logs` | `<home>/seagent/run` |
//!
//! On Android and iOS the host app is expected to set `SEAGENT_HOME` to its sandbox directory
//! (portable mode, handled before any of this); the table row is only the fallback.
//!
//! [`which_in_pathext`] is the Windows `PATH` search: `PATHEXT` extensions (`.COM;.EXE;.BAT;
//! .CMD` by default) are tried in order, and the executable bit does not exist.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Which directory convention applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux and every other Unix without a convention of its own (XDG / FHS).
    Linux,
    MacOs,
    Windows,
    Android,
    Ios,
}

impl Os {
    /// The OS this binary was built for.
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "ios") {
            Os::Ios
        } else if cfg!(target_os = "android") {
            Os::Android
        } else {
            Os::Linux
        }
    }
}

/// A full set of default directories (see the module table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    pub config: PathBuf,
    pub data: PathBuf,
    pub cache: PathBuf,
    pub logs: PathBuf,
    pub runtime: PathBuf,
    /// Why (shown by `seagent config path`).
    pub reason: &'static str,
}

fn abs(v: Option<String>) -> Option<PathBuf> {
    v.filter(|s| !s.is_empty()).map(PathBuf::from).filter(|p| p.is_absolute() || looks_like_windows_abs(p))
}

/// `C:\…` / `\\server\…` count as absolute even when the tests run on a Unix host.
fn looks_like_windows_abs(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let b = s.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || s.starts_with("\\\\")
}

/// Join with `\` for Windows paths regardless of the host (keeps the pure functions testable).
fn wjoin(base: &Path, parts: &[&str]) -> PathBuf {
    let mut s = base.to_string_lossy().trim_end_matches(['\\', '/']).to_string();
    for p in parts {
        s.push('\\');
        s.push_str(p);
    }
    PathBuf::from(s)
}

/// The per-user default directories of `os`; `None` for [`Os::Linux`], where the XDG rules in
/// `crate::layout` apply unchanged. `home` is the already resolved home directory.
pub fn user_dirs(os: Os, env: &dyn Fn(&str) -> Option<String>, home: &Path) -> Option<Dirs> {
    match os {
        Os::Linux => None,
        Os::MacOs => {
            let base = home.join("Library").join("Application Support").join("seagent");
            Some(Dirs { config: base.join("config"), data: base.join("data"), cache: home.join("Library").join("Caches").join("seagent"), logs: home.join("Library").join("Logs").join("seagent"), runtime: base.join("run"), reason: "default (macOS ~/Library directories)" })
        }
        Os::Windows => {
            let roaming = abs(env("APPDATA")).unwrap_or_else(|| wjoin(home, &["AppData", "Roaming"]));
            let local = abs(env("LOCALAPPDATA")).unwrap_or_else(|| wjoin(home, &["AppData", "Local"]));
            let data = wjoin(&local, &["seagent", "data"]);
            Some(Dirs { config: wjoin(&roaming, &["seagent"]), logs: wjoin(&data, &["logs"]), cache: wjoin(&local, &["seagent", "cache"]), runtime: wjoin(&local, &["seagent", "run"]), data, reason: "default (Windows %APPDATA% / %LOCALAPPDATA%)" })
        }
        Os::Android | Os::Ios => {
            let base = home.join("seagent");
            let data = base.join("data");
            Some(Dirs { config: base.join("config"), logs: data.join("logs"), cache: base.join("cache"), runtime: base.join("run"), data, reason: "app sandbox fallback (the host app should set SEAGENT_HOME)" })
        }
    }
}

/// The system-service directories of `os`; `None` where the FHS layout of `crate::layout`
/// applies (Linux and the other Unixes).
pub fn system_dirs(os: Os, env: &dyn Fn(&str) -> Option<String>) -> Option<Dirs> {
    if os != Os::Windows {
        return None;
    }
    let pd = abs(env("ProgramData")).unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    let base = wjoin(&pd, &["seagent"]);
    Some(Dirs { config: wjoin(&base, &["config"]), data: wjoin(&base, &["data"]), cache: wjoin(&base, &["cache"]), logs: wjoin(&base, &["logs"]), runtime: wjoin(&base, &["run"]), reason: "Windows service (%ProgramData%\\seagent)" })
}

/// The first executable called `name` on `PATH` (Unix: executable bit; Windows: `PATHEXT`).
/// Same as `crate::layout::which`.
pub fn which(name: &str) -> Option<PathBuf> {
    crate::layout::which(name)
}

/// Windows executable search: `name` in each `;`-separated directory of `path`, trying the
/// `PATHEXT` extensions (`pathext`, default `.COM;.EXE;.BAT;.CMD`). A `name` that already ends
/// in one of them is tried as is first; a `name` with a path separator is not searched for.
pub fn which_in_pathext(name: &str, path: Option<&OsStr>, pathext: Option<&str>) -> Option<PathBuf> {
    let exts: Vec<String> = pathext.filter(|s| !s.trim().is_empty()).unwrap_or(".COM;.EXE;.BAT;.CMD").split(';').map(|e| e.trim().to_ascii_lowercase()).filter(|e| e.starts_with('.') && e.len() > 1).collect();
    let has_ext = Path::new(name).extension().is_some_and(|e| exts.contains(&format!(".{}", e.to_string_lossy().to_ascii_lowercase())));
    let probe = |base: PathBuf| -> Option<PathBuf> {
        if has_ext && base.is_file() {
            return Some(base);
        }
        exts.iter().map(|e| PathBuf::from(format!("{}{e}", base.display()))).find(|p| p.is_file())
    };
    if name.contains(['/', '\\']) {
        return probe(PathBuf::from(name));
    }
    let path = path?.to_string_lossy().into_owned();
    path.split(';').map(|d| d.trim().trim_matches('"')).filter(|d| !d.is_empty()).find_map(|d| probe(Path::new(d).join(name)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    #[test]
    fn linux_keeps_the_xdg_rules() {
        assert_eq!(user_dirs(Os::Linux, &env(&[]), Path::new("/h")), None);
        assert_eq!(system_dirs(Os::Linux, &env(&[])), None);
        assert_eq!(system_dirs(Os::MacOs, &env(&[])), None);
        if cfg!(target_os = "linux") {
            assert_eq!(Os::current(), Os::Linux);
        }
    }

    #[test]
    fn windows_uses_appdata_and_localappdata() {
        let e = env(&[("APPDATA", "C:\\Users\\u\\AppData\\Roaming"), ("LOCALAPPDATA", "C:\\Users\\u\\AppData\\Local")]);
        let d = user_dirs(Os::Windows, &e, Path::new("C:\\Users\\u")).unwrap();
        assert_eq!(d.config, PathBuf::from("C:\\Users\\u\\AppData\\Roaming\\seagent"));
        assert_eq!(d.data, PathBuf::from("C:\\Users\\u\\AppData\\Local\\seagent\\data"));
        assert_eq!(d.cache, PathBuf::from("C:\\Users\\u\\AppData\\Local\\seagent\\cache"));
        assert_eq!(d.runtime, PathBuf::from("C:\\Users\\u\\AppData\\Local\\seagent\\run"));
        assert_eq!(d.logs, PathBuf::from("C:\\Users\\u\\AppData\\Local\\seagent\\data\\logs"));
        // missing variables fall back to the profile; relative values are ignored
        let d = user_dirs(Os::Windows, &env(&[("APPDATA", "rel")]), Path::new("C:\\Users\\u")).unwrap();
        assert_eq!(d.config, PathBuf::from("C:\\Users\\u\\AppData\\Roaming\\seagent"));
        let s = system_dirs(Os::Windows, &env(&[("ProgramData", "D:\\PD")])).unwrap();
        assert_eq!((s.config, s.runtime), (PathBuf::from("D:\\PD\\seagent\\config"), PathBuf::from("D:\\PD\\seagent\\run")));
    }

    #[test]
    fn macos_and_mobile_directories() {
        let d = user_dirs(Os::MacOs, &env(&[]), Path::new("/Users/u")).unwrap();
        assert_eq!(d.config, Path::new("/Users/u").join("Library/Application Support/seagent/config"));
        assert_eq!(d.cache, Path::new("/Users/u").join("Library/Caches/seagent"));
        let d = user_dirs(Os::Ios, &env(&[]), Path::new("/var/mobile/app")).unwrap();
        assert_eq!(d.data, Path::new("/var/mobile/app").join("seagent/data"));
        assert!(user_dirs(Os::Android, &env(&[]), Path::new("/data/x")).unwrap().reason.contains("SEAGENT_HOME"));
    }

    #[test]
    fn pathext_search() {
        let t = crate::tmp::TempDir::new("seagent-which-pathext");
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("tool.exe"), "").unwrap();
        std::fs::write(a.join("tool"), "").unwrap(); // extensionless: never an executable on Windows
        std::fs::write(a.join("run.cmd"), "").unwrap();
        let path = format!("{};\"{}\"", a.display(), b.display());
        let p = Some(OsStr::new(&path));
        assert_eq!(which_in_pathext("tool", p, None), Some(b.join("tool.exe")));
        assert_eq!(which_in_pathext("tool.exe", p, Some(".EXE")), Some(b.join("tool.exe")));
        assert_eq!(which_in_pathext("run", p, Some(".EXE;.CMD")), Some(a.join("run.cmd")));
        assert_eq!(which_in_pathext("run", p, Some(".EXE")), None);
        assert_eq!(which_in_pathext("missing", p, None), None);
        assert_eq!(which_in_pathext("tool", None, None), None);
        let direct = b.join("tool").display().to_string();
        assert_eq!(which_in_pathext(&direct, None, None), Some(b.join("tool.exe")));
    }
}
