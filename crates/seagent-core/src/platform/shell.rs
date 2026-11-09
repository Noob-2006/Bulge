//! Which shell runs a command line, and how it is invoked.
//!
//! Call sites used to spell `Command::new("bash").arg("-c")`, `bash -lc`, `sh -c` or
//! `/bin/sh -c` themselves. [`Style`] names those four spellings, and [`command`] builds them:
//!
//! * **Unix** — exactly the old spelling (`bash` / `sh` looked up on `$PATH` by `exec`, the
//!   fixed `/bin/sh`). No probing, no caching: nothing changes on Linux. On Android, where
//!   there is no bash, the bash styles fall back to `sh` (the system `/system/bin/sh`).
//! * **Windows** — one [`active`] shell, picked once: `SEAGENT_SHELL` if set; else a real bash
//!   (Git for Windows, MSYS2, or a `bash.exe` on `PATH` that is *not* the WSL launcher in
//!   `System32` / `WindowsApps`, which would run the command in a Linux VM with other files);
//!   else PowerShell 7 (`pwsh`); else Windows PowerShell. Bash styles run as `bash -c` /
//!   `bash -lc`; PowerShell as `-NoProfile -NonInteractive -Command` (login: with the profile).
//!
//! [`Shell::prompt_note`] is the sentence the system prompt carries so the model writes the
//! right syntax.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The family of the shell that will interpret a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    /// GNU bash (Linux, macOS, Git Bash, MSYS2).
    Bash,
    /// A POSIX `sh` (dash, busybox, Android's mksh).
    Sh,
    /// PowerShell 7+ (`pwsh`).
    Pwsh,
    /// Windows PowerShell 5.1 (`powershell.exe`).
    WindowsPowerShell,
}

impl ShellKind {
    /// Does it take POSIX shell syntax?
    pub fn is_posix(self) -> bool {
        matches!(self, ShellKind::Bash | ShellKind::Sh)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ShellKind::Bash => "bash",
            ShellKind::Sh => "sh",
            ShellKind::Pwsh => "pwsh",
            ShellKind::WindowsPowerShell => "powershell",
        }
    }
}

/// How a call site starts its shell: the Unix spelling it had before the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `bash -c SCRIPT`
    Bash,
    /// `bash -lc SCRIPT` (login shell: profile, PATH additions)
    BashLogin,
    /// `sh -c SCRIPT` (`sh` from `$PATH`)
    Sh,
    /// `/bin/sh -c SCRIPT` (the fixed system shell)
    BinSh,
}

impl Style {
    /// `Bash` or `BashLogin`, from a request's `login` flag.
    pub fn bash(login: bool) -> Style {
        if login {
            Style::BashLogin
        } else {
            Style::Bash
        }
    }
    fn login(self) -> bool {
        self == Style::BashLogin
    }
}

/// The shell [`command`] uses on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    pub kind: ShellKind,
    /// Program to execute (a bare name is looked up on `PATH`).
    pub program: PathBuf,
    /// Why this one was chosen (for `seagent doctor`).
    pub reason: String,
}

impl Shell {
    /// One sentence for the system prompt.
    pub fn prompt_note(&self) -> String {
        match self.kind {
            ShellKind::Bash => format!("Shell commands run in bash ({}).", self.program.display()),
            ShellKind::Sh => format!("Shell commands run in a POSIX sh ({}); bash-only syntax is not available.", self.program.display()),
            ShellKind::Pwsh => "Shell commands run in PowerShell 7 (pwsh) on Windows: use PowerShell syntax and cmdlets, not bash.".into(),
            ShellKind::WindowsPowerShell => "Shell commands run in Windows PowerShell 5.1 on Windows: use PowerShell syntax and cmdlets, not bash (no `&&`; use `;` or `if ($?)`).".into(),
        }
    }

    /// Arguments that make this shell run `script` (also for building a remote or PTY argv).
    pub fn args(&self, style: Style, script: &str) -> Vec<OsString> {
        match self.kind {
            ShellKind::Bash => vec![if style.login() { "-lc" } else { "-c" }.into(), script.into()],
            ShellKind::Sh => vec!["-c".into(), script.into()],
            ShellKind::Pwsh | ShellKind::WindowsPowerShell => {
                let mut a: Vec<OsString> = vec![];
                if !style.login() {
                    a.push("-NoProfile".into());
                }
                a.extend(["-NonInteractive".into(), "-Command".into(), script.into()]);
                a
            }
        }
    }
}

/// The shell of this machine (decided once per process on Windows / Android).
pub fn active() -> &'static Shell {
    static SHELL: std::sync::OnceLock<Shell> = std::sync::OnceLock::new();
    SHELL.get_or_init(detect)
}

#[cfg(all(unix, not(target_os = "android")))]
fn detect() -> Shell {
    Shell { kind: ShellKind::Bash, program: "bash".into(), reason: "bash from PATH".into() }
}

#[cfg(target_os = "android")]
fn detect() -> Shell {
    match super::layout::which("bash") {
        Some(p) => Shell { kind: ShellKind::Bash, program: p, reason: "bash found on PATH".into() },
        None => Shell { kind: ShellKind::Sh, program: "sh".into(), reason: "Android: no bash on PATH, system sh".into() },
    }
}

#[cfg(windows)]
fn detect() -> Shell {
    let env = |k: &str| std::env::var(k).ok();
    detect_windows_with(&env, &|p: &Path| p.is_file(), &super::layout::which)
}

#[cfg(not(any(unix, windows)))]
fn detect() -> Shell {
    Shell { kind: ShellKind::Sh, program: "sh".into(), reason: "no shell detection on this target".into() }
}

/// `(program, args)` for `script` in `style`. Unix: the old literal spelling.
pub fn argv(style: Style, script: &str) -> (OsString, Vec<OsString>) {
    #[cfg(all(unix, not(target_os = "android")))]
    {
        let (prog, flag) = match style {
            Style::Bash => ("bash", "-c"),
            Style::BashLogin => ("bash", "-lc"),
            Style::Sh => ("sh", "-c"),
            Style::BinSh => ("/bin/sh", "-c"),
        };
        (prog.into(), vec![flag.into(), script.into()])
    }
    #[cfg(not(all(unix, not(target_os = "android"))))]
    {
        if cfg!(target_os = "android") && matches!(style, Style::Sh | Style::BinSh) {
            return ("sh".into(), vec!["-c".into(), script.into()]);
        }
        let sh = active();
        (sh.program.clone().into_os_string(), sh.args(style, script))
    }
}

/// A `Command` that runs `script` in `style` (see the module docs).
pub fn command(style: Style, script: &str) -> Command {
    let (prog, args) = argv(style, script);
    let mut c = Command::new(prog);
    c.args(args);
    c
}

/// A path spelled for the shell that will read it (as a script argument or inside a script).
/// Unix: unchanged. Windows: without the verbatim `\\?\` prefix, and with `/` separators when
/// the shell is a bash (MSYS bash reads `C:/x/y.sh`, but eats the backslashes of `C:\x\y.sh`).
pub fn path_arg(p: &Path) -> OsString {
    #[cfg(windows)]
    {
        let plain = super::layout::simplify_verbatim(p);
        if active().kind.is_posix() {
            return plain.to_string_lossy().replace('\\', "/").into();
        }
        plain.into_os_string()
    }
    #[cfg(not(windows))]
    {
        p.as_os_str().to_os_string()
    }
}

/// [`path_arg`] as text, for splicing into a script (quote it for the shell yourself).
pub fn path_str(p: &Path) -> String {
    path_arg(p).to_string_lossy().into_owned()
}

/// `bash -c SCRIPT` (or this machine's shell).
pub fn shell_command(script: &str) -> Command {
    command(Style::Bash, script)
}

/// `bash -lc SCRIPT` (or this machine's shell, with its profile).
pub fn login_shell_command(script: &str) -> Command {
    command(Style::BashLogin, script)
}

/// The Windows choice as a pure function (testable on any host). `env` reads variables,
/// `is_file` checks a candidate, `which` searches `PATH` (with `PATHEXT`).
pub fn detect_windows_with(env: &dyn Fn(&str) -> Option<String>, is_file: &dyn Fn(&Path) -> bool, which: &dyn Fn(&str) -> Option<PathBuf>) -> Shell {
    if let Some(s) = env("SEAGENT_SHELL").filter(|s| !s.trim().is_empty()) {
        let program = PathBuf::from(s.trim());
        let name = s.trim().rsplit(['/', '\\']).next().unwrap_or("").to_ascii_lowercase();
        let kind = if name.starts_with("pwsh") {
            ShellKind::Pwsh
        } else if name.starts_with("powershell") {
            ShellKind::WindowsPowerShell
        } else if name.starts_with("bash") {
            ShellKind::Bash
        } else {
            ShellKind::Sh
        };
        return Shell { kind, program, reason: "SEAGENT_SHELL".into() };
    }
    let mut candidates: Vec<(PathBuf, &str)> = vec![];
    for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
        if let Some(pf) = env(var).filter(|v| !v.is_empty()) {
            candidates.push((PathBuf::from(format!("{pf}\\Git\\bin\\bash.exe")), "Git for Windows"));
        }
    }
    if let Some(la) = env("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        candidates.push((PathBuf::from(format!("{la}\\Programs\\Git\\bin\\bash.exe")), "Git for Windows (per-user)"));
    }
    if let Some(root) = env("MSYS2_ROOT").filter(|v| !v.is_empty()) {
        candidates.push((PathBuf::from(format!("{root}\\usr\\bin\\bash.exe")), "MSYS2"));
    }
    candidates.push((PathBuf::from("C:\\msys64\\usr\\bin\\bash.exe"), "MSYS2"));
    for (p, what) in candidates {
        if is_file(&p) {
            return Shell { kind: ShellKind::Bash, program: p, reason: format!("{what} bash") };
        }
    }
    if let Some(p) = which("bash").filter(|p| !is_wsl_launcher(p, env("SystemRoot").as_deref())) {
        return Shell { kind: ShellKind::Bash, program: p, reason: "bash.exe on PATH".into() };
    }
    if let Some(p) = which("pwsh") {
        return Shell { kind: ShellKind::Pwsh, program: p, reason: "no bash found; PowerShell 7".into() };
    }
    let program = which("powershell").unwrap_or_else(|| PathBuf::from("powershell.exe"));
    Shell { kind: ShellKind::WindowsPowerShell, program, reason: "no bash or pwsh found; Windows PowerShell".into() }
}

/// `System32\bash.exe` and the `WindowsApps` alias start WSL, not a Windows bash.
fn is_wsl_launcher(p: &Path, system_root: Option<&str>) -> bool {
    let s = p.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    if let Some(root) = system_root.filter(|r| !r.is_empty()) {
        let root = root.replace('/', "\\").to_ascii_lowercase();
        let root = root.trim_end_matches('\\');
        if s == format!("{root}\\system32\\bash.exe") || s == format!("{root}\\sysnative\\bash.exe") {
            return true;
        }
    }
    s.ends_with("\\windows\\system32\\bash.exe") || s.contains("\\windowsapps\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn pick(env: &[(&str, &str)], files: &[&str], on_path: &[(&str, &str)]) -> Shell {
        let env: HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let files: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
        let path: HashMap<String, PathBuf> = on_path.iter().map(|(k, v)| (k.to_string(), PathBuf::from(v))).collect();
        detect_windows_with(&|k| env.get(k).cloned(), &|p| files.iter().any(|f| f == p), &|n| path.get(n).cloned())
    }

    #[test]
    fn windows_prefers_git_bash_then_pwsh_then_powershell() {
        let pf = [("ProgramFiles", "C:\\Program Files"), ("SystemRoot", "C:\\Windows")];
        let s = pick(&pf, &["C:\\Program Files\\Git\\bin\\bash.exe"], &[("pwsh", "C:\\pwsh\\pwsh.exe")]);
        assert_eq!((s.kind, s.program), (ShellKind::Bash, PathBuf::from("C:\\Program Files\\Git\\bin\\bash.exe")));
        let s = pick(&pf, &["C:\\msys64\\usr\\bin\\bash.exe"], &[]);
        assert_eq!(s.kind, ShellKind::Bash);
        assert!(s.reason.contains("MSYS2"));
        // the WSL launcher on PATH is not a Windows bash
        let s = pick(&pf, &[], &[("bash", "C:\\Windows\\System32\\bash.exe"), ("pwsh", "C:\\pwsh\\pwsh.exe")]);
        assert_eq!(s.kind, ShellKind::Pwsh);
        let s = pick(&pf, &[], &[("bash", "C:\\Users\\u\\AppData\\Local\\Microsoft\\WindowsApps\\bash.exe")]);
        assert_eq!((s.kind, s.program), (ShellKind::WindowsPowerShell, PathBuf::from("powershell.exe")));
        let s = pick(&pf, &[], &[("bash", "D:\\tools\\cygwin\\bin\\bash.exe")]);
        assert_eq!(s.kind, ShellKind::Bash);
        let s = pick(&[("SEAGENT_SHELL", "C:\\x\\pwsh.exe")], &["C:\\Program Files\\Git\\bin\\bash.exe"], &[]);
        assert_eq!((s.kind, s.reason.as_str()), (ShellKind::Pwsh, "SEAGENT_SHELL"));
    }

    #[test]
    fn powershell_arguments() {
        let s = Shell { kind: ShellKind::Pwsh, program: "pwsh".into(), reason: String::new() };
        assert_eq!(s.args(Style::Bash, "ls"), ["-NoProfile", "-NonInteractive", "-Command", "ls"].map(OsString::from));
        assert_eq!(s.args(Style::BashLogin, "ls"), ["-NonInteractive", "-Command", "ls"].map(OsString::from));
        let b = Shell { kind: ShellKind::Bash, program: "bash".into(), reason: String::new() };
        assert_eq!(b.args(Style::BashLogin, "ls"), ["-lc", "ls"].map(OsString::from));
        assert!(s.prompt_note().contains("PowerShell") && b.prompt_note().contains("bash"));
        assert!(ShellKind::Bash.is_posix() && !ShellKind::Pwsh.is_posix());
    }

    #[cfg(all(unix, not(target_os = "android")))]
    #[test]
    fn unix_spelling_is_unchanged() {
        let a = |s| {
            let (p, v) = argv(s, "echo hi");
            (p.into_string().unwrap(), v.into_iter().map(|x| x.into_string().unwrap()).collect::<Vec<_>>())
        };
        assert_eq!(a(Style::Bash), ("bash".into(), vec!["-c".into(), "echo hi".into()]));
        assert_eq!(a(Style::BashLogin), ("bash".into(), vec!["-lc".into(), "echo hi".into()]));
        assert_eq!(a(Style::Sh), ("sh".into(), vec!["-c".into(), "echo hi".into()]));
        assert_eq!(a(Style::BinSh), ("/bin/sh".into(), vec!["-c".into(), "echo hi".into()]));
        assert_eq!(Style::bash(true), Style::BashLogin);
        let out = shell_command("printf %s \"$((1+2))\"").output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "3");
        assert_eq!(active().kind, ShellKind::Bash);
    }
}
