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

/// `%LOCALAPPDATA%\Microsoft\WindowsApps\python3.exe` / `python.exe` / `bash.exe` are App
/// Execution Aliases: they open the Store (or start WSL) instead of being the program.
pub fn is_windows_apps_alias(p: &Path) -> bool {
    p.to_string_lossy().replace('/', "\\").to_ascii_lowercase().contains("\\microsoft\\windowsapps\\")
}

/// The Python 3 interpreter as `(program, leading args)`, `None` when there is none.
/// Unix: `python3` from `PATH`, as always. Windows: the `py -3` launcher first, then a real
/// `python3.exe` / `python.exe` on `PATH`, never the WindowsApps Store alias (it exits 9009).
pub fn python3() -> Option<(PathBuf, Vec<String>)> {
    #[cfg(windows)]
    {
        static PY: std::sync::OnceLock<Option<(PathBuf, Vec<String>)>> = std::sync::OnceLock::new();
        PY.get_or_init(|| python3_windows_with(&which)).clone()
    }
    #[cfg(not(windows))]
    {
        which("python3").map(|_| (PathBuf::from("python3"), vec![]))
    }
}

/// The Windows choice of [`python3`] as a pure function (testable on any host).
pub fn python3_windows_with(which: &dyn Fn(&str) -> Option<PathBuf>) -> Option<(PathBuf, Vec<String>)> {
    if let Some(py) = which("py").filter(|p| !is_windows_apps_alias(p)) {
        return Some((py, vec!["-3".into()]));
    }
    ["python3", "python"].iter().find_map(|n| which(n).filter(|p| !is_windows_apps_alias(p))).map(|p| (p, vec![]))
}

/// A `Command` for Python 3 (see [`python3`]). Unix: exactly `python3`. Windows: falls back to
/// the bare name `python` so the spawn error names what is missing.
pub fn python3_command() -> std::process::Command {
    #[cfg(windows)]
    {
        match python3() {
            Some((p, args)) => {
                let mut c = std::process::Command::new(p);
                c.args(args);
                c
            }
            None => std::process::Command::new("python"),
        }
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("python3")
    }
}

/// A `Command` for a configured program name (MCP servers, LSP servers, agent CLIs, model
/// runtimes). Unix: exactly `Command::new(name)`. Windows: the name is resolved through
/// `PATHEXT` (npm CLIs are `.cmd` shims), a bare `python3` / `python` means [`python3`]
/// (the `py -3` launcher) rather than the WindowsApps Store alias, which only prints
/// "Python was not found" and exits 9009 — configs written on Linux say `python3` — and a
/// bare `sh` / `bash` means [`bash`] (Git Bash / MSYS2) when there is one.
pub fn program_command(name: impl AsRef<OsStr>) -> std::process::Command {
    #[cfg(windows)]
    {
        let raw = name.as_ref();
        let name = raw.to_string_lossy();
        let bare = name.trim_end_matches(".exe").to_ascii_lowercase();
        if bare == "python3" || bare == "python" {
            if let Some((p, args)) = python3() {
                let mut c = std::process::Command::new(p);
                c.args(args);
                // Pipes speak UTF-8 JSON (MCP, ACP, LSP); Windows Python would decode them in
                // the ANSI code page. UTF-8 mode (`-X utf8`, which `-I` / `-E` scripts honour
                // too) unless the user chose otherwise with PYTHONUTF8.
                if std::env::var_os("PYTHONUTF8").is_none() {
                    c.args(["-X", "utf8"]);
                }
                return c;
            }
        }
        // `sh -c …` / `bash script` in a config: Git Bash / MSYS2, never WSL's `bash.exe`.
        if bare == "sh" || bare == "bash" {
            if let Some(b) = bash() {
                return std::process::Command::new(b);
            }
        }
        if let Some(p) = which(&name) {
            return std::process::Command::new(p);
        }
        // A POSIX tool a Linux config names (`cat`, `grep`, `false`…): Git for Windows / MSYS2
        // ship them next to their bash, outside PATH.
        if !name.contains(['/', '\\']) {
            if let Some(p) = bash().and_then(|b| posix_tools_dir(&b)).map(|d| d.join(format!("{bare}.exe"))).filter(|p| p.is_file()) {
                return std::process::Command::new(p);
            }
        }
        std::process::Command::new(raw)
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new(name)
    }
}

/// [`program_command`] plus its arguments. Unix: `Command::new(name).args(args)`. Windows:
/// when the program is an MSYS2 / Cygwin one (Git Bash, its `usr\bin` tools), every argument
/// goes through [`msys_quote`] — the MSYS runtime globs and brace-expands any argument the
/// command line leaves unquoted, so `[{"a":1,"b":2}]` would otherwise split.
pub fn program_command_args<S: AsRef<OsStr>>(name: impl AsRef<OsStr>, args: &[S]) -> std::process::Command {
    let mut c = program_command(name);
    msys_args(&mut c, args);
    c
}

/// Append `args` to `c` (see [`program_command_args`]): plain `args` on Unix and for native
/// Windows programs, [`msys_quote`]d raw arguments for an MSYS2 program.
pub fn msys_args<S: AsRef<OsStr>>(c: &mut std::process::Command, args: &[S]) {
    #[cfg(windows)]
    if is_msys_program(Path::new(c.get_program())) {
        use std::os::windows::process::CommandExt;
        for a in args {
            c.raw_arg(msys_quote(&a.as_ref().to_string_lossy()));
        }
        return;
    }
    c.args(args);
}

/// One argument for an MSYS2 program's command line: always inside double quotes (so the
/// runtime neither globs nor brace-expands it), with the MSVCRT escaping the runtime's own
/// parser undoes — `\"` for a quote, backslashes doubled only before a quote or the end.
pub fn msys_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut slashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}

/// Is `program` an MSYS2 / Cygwin executable (its directory carries the runtime DLL, or it is
/// the platform bash)? Always false off Windows.
pub fn is_msys_program(program: &Path) -> bool {
    #[cfg(windows)]
    {
        let Some(dir) = program.parent().filter(|d| !d.as_os_str().is_empty()) else { return false };
        if dir.join("msys-2.0.dll").is_file() || dir.join("cygwin1.dll").is_file() {
            return true;
        }
        bash().is_some_and(|b| b == program || posix_tools_dir(&b).is_some_and(|d| d == dir))
    }
    #[cfg(not(windows))]
    {
        let _ = program;
        false
    }
}

/// The `usr\bin` holding the coreutils of a Git for Windows / MSYS2 bash: Git's
/// `…\Git\bin\bash.exe` → `…\Git\usr\bin`; MSYS2's bash already lives there.
#[cfg(windows)]
fn posix_tools_dir(bash: &Path) -> Option<PathBuf> {
    let dir = bash.parent()?;
    let usr_bin = if dir.ends_with("usr\\bin") || dir.ends_with("usr/bin") { dir.to_path_buf() } else { dir.parent()?.join("usr").join("bin") };
    usr_bin.is_dir().then_some(usr_bin)
}

/// A bash that really is bash: Unix `bash` from `PATH`; Windows the platform shell's bash (Git
/// Bash / MSYS2 / `SEAGENT_SHELL`), never `System32\bash.exe` (the WSL launcher) or a
/// WindowsApps alias. `None` when there is none.
pub fn bash() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let sh = super::shell::active();
        (sh.kind == super::shell::ShellKind::Bash).then(|| sh.program.clone())
    }
    #[cfg(not(windows))]
    {
        which("bash")
    }
}

/// `std::fs::canonicalize` without Windows' verbatim prefix: `\\?\C:\x` → `C:\x`,
/// `\\?\UNC\srv\share` → `\\srv\share` (cmd.exe, Task Scheduler and many tools reject the
/// verbatim form as a working directory or argument). Unix: `std::fs::canonicalize` unchanged.
pub fn canonicalize(p: &Path) -> std::io::Result<PathBuf> {
    let c = std::fs::canonicalize(p)?;
    #[cfg(windows)]
    let c = simplify_verbatim(&c);
    Ok(c)
}

/// The ordinary spelling of a verbatim Windows path, when it has one (drive or UNC path short
/// enough for the classic APIs); anything else is returned unchanged.
pub fn simplify_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    let plain = if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\").filter(|r| r.len() >= 2 && r.as_bytes()[1] == b':' && r.as_bytes()[0].is_ascii_alphabetic()) {
        rest.to_string()
    } else {
        return p.to_path_buf();
    };
    if plain.len() >= 260 {
        return p.to_path_buf();
    }
    PathBuf::from(plain)
}

/// A *relative* path as the model sees it (tool output, patch summaries): `/` between components
/// on every OS, so `src\a.rs` on Windows reads `src/a.rs`, as models and patches expect.
/// Absolute paths are spelled natively (`C:\Users\…`). Unix: `p.display()` unchanged.
pub fn model_path(p: &Path) -> String {
    let s = p.display().to_string();
    #[cfg(windows)]
    if p.is_relative() {
        return s.replace('\\', "/");
    }
    s
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
    fn windows_python_skips_the_store_alias_and_prefers_py() {
        let alias = PathBuf::from(r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\python3.exe");
        let only_alias = |n: &str| (n == "python3" || n == "python").then(|| alias.clone());
        assert_eq!(python3_windows_with(&only_alias), None, "the Store alias is not a Python");
        let real = |n: &str| match n {
            "py" => Some(PathBuf::from(r"C:\Windows\py.exe")),
            "python3" => Some(alias.clone()),
            "python" => Some(PathBuf::from(r"C:\Python312\python.exe")),
            _ => None,
        };
        assert_eq!(python3_windows_with(&real), Some((PathBuf::from(r"C:\Windows\py.exe"), vec!["-3".to_string()])));
        let no_py = |n: &str| if n == "py" { None } else { real(n) };
        assert_eq!(python3_windows_with(&no_py), Some((PathBuf::from(r"C:\Python312\python.exe"), vec![])));
        assert!(is_windows_apps_alias(&alias) && !is_windows_apps_alias(Path::new("/usr/bin/python3")));
    }

    #[test]
    fn verbatim_prefix_is_dropped() {
        assert_eq!(simplify_verbatim(Path::new(r"\\?\C:\Users\u\ws")), PathBuf::from(r"C:\Users\u\ws"));
        assert_eq!(simplify_verbatim(Path::new(r"\\?\UNC\srv\share\x")), PathBuf::from(r"\\srv\share\x"));
        assert_eq!(simplify_verbatim(Path::new(r"\\?\Volume{abc}\x")), PathBuf::from(r"\\?\Volume{abc}\x"));
        assert_eq!(simplify_verbatim(Path::new("/home/u")), PathBuf::from("/home/u"));
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

    #[test]
    fn msys_quote_always_quotes_with_msvcrt_escapes() {
        assert_eq!(msys_quote("*"), "\"*\"");
        assert_eq!(msys_quote(""), "\"\"");
        assert_eq!(msys_quote(r#"[{"n":3}]"#), r#""[{\"n\":3}]""#);
        assert_eq!(msys_quote(r"C:\dir\"), r#""C:\dir\\""#);
        assert_eq!(msys_quote(r#"a\"b"#), r#""a\\\"b""#);
        assert!(!is_msys_program(Path::new("/usr/bin/printf")) || cfg!(windows));
    }

    /// The arguments arrive byte for byte: Unix `printf`; Windows Git Bash's own `printf.exe`
    /// (an MSYS2 program that would glob `*`, brace-expand `{a,b}` and drop JSON quotes from a
    /// plainly quoted command line).
    #[test]
    fn program_command_args_survive_an_msys_runtime() {
        let args = [r#"[{"n":3,"t":"c"},{"n":1}]"#, "*", "{a,b}", "a b", r#"say "hi""#, r"trail\", "", "~"];
        let mut c = program_command_args("printf", &["%s|".to_string()].into_iter().chain(args.iter().map(|s| s.to_string())).collect::<Vec<_>>());
        if cfg!(windows) && !is_msys_program(Path::new(c.get_program())) {
            eprintln!("skipped: no Git Bash / MSYS2 printf.exe on this machine");
            return;
        }
        let out = c.output().expect("printf runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout), args.iter().map(|a| format!("{a}|")).collect::<String>());
    }
}
