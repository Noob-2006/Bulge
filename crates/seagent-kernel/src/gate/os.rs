//! The Privilege gate's Windows and macOS knowledge: system paths, sensitive files and the
//! commands that need an administrator or change the machine.
//!
//! These are pure functions compiled on every host (so their tests run everywhere); the gate
//! consults them only on the matching OS (`cfg!(windows)` / `cfg!(target_os = "macos")`), which
//! keeps the Linux verdicts exactly what they were (`sc`, `format` or `launchctl` mean nothing
//! there, and must not start asking).
//!
//! Commands reach the gate through the POSIX shell parser, so a Windows path may arrive with
//! its backslashes eaten (`C:\Windows` → `C:Windows`): both spellings, `/` separators and the
//! `%SystemRoot%` / `$env:windir` forms are recognised. Windows names are case-insensitive and
//! may carry a directory and `.exe`.

use crate::shell::Simple;

/// `C:\Windows\System32\reg.exe` → `reg`; `Remove-Item` → `remove-item`.
pub fn win_name(argv0: &str) -> String {
    let base = argv0.rsplit(['/', '\\']).next().unwrap_or(argv0).to_ascii_lowercase();
    for ext in [".exe", ".com", ".cmd", ".bat", ".ps1"] {
        if let Some(s) = base.strip_suffix(ext) {
            return s.to_string();
        }
    }
    base
}

/// Lower-case, `/` separators, environment spellings of the system directories expanded,
/// `.` / `..` resolved.
fn win_norm(p: &str) -> String {
    let mut s = p.trim().trim_matches(['"', '\'']).replace('\\', "/").to_ascii_lowercase();
    for (var, val) in [("%systemroot%", "c:/windows"), ("%windir%", "c:/windows"), ("$env:systemroot", "c:/windows"), ("$env:windir", "c:/windows"), ("%programfiles%", "c:/program files"), ("$env:programfiles", "c:/program files"), ("%programdata%", "c:/programdata"), ("$env:programdata", "c:/programdata"), ("%systemdrive%", "c:"), ("$env:systemdrive", "c:")] {
        if let Some(rest) = s.strip_prefix(var) {
            s = format!("{val}{rest}");
            break;
        }
    }
    // `\\?\C:\…` and `//./c:` device prefixes name the same file.
    for pre in ["//?/", "//./"] {
        if let Some(rest) = s.strip_prefix(pre) {
            if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
                s = rest.to_string();
            }
        }
    }
    let (drive, rest) = if s.len() >= 2 && s.as_bytes()[1] == b':' && s.as_bytes()[0].is_ascii_alphabetic() { (s[..2].to_string(), s[2..].to_string()) } else { (String::new(), s.clone()) };
    let mut parts: Vec<&str> = vec![];
    for c in rest.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if drive.is_empty() {
        if rest.starts_with('/') {
            format!("/{}", parts.join("/"))
        } else {
            parts.join("/")
        }
    } else {
        format!("{drive}/{}", parts.join("/"))
    }
}

/// Directories (under any drive letter) that belong to the operating system or to all users.
const WIN_SYSTEM_DIRS: &[&str] = &["windows", "program files", "program files (x86)", "programdata/microsoft", "system volume information", "$recycle.bin", "boot", "recovery", "efi", "bootmgr", "pagefile.sys", "hiberfil.sys", "swapfile.sys"];

/// Is `p` a Windows system location: a drive root, `C:\Windows`, `Program Files`, a raw
/// device (`\\.\PhysicalDrive0`, `\\.\C:`) or a machine-wide registry hive (`HKLM:\…`)?
pub fn windows_system_path(p: &str) -> bool {
    let raw = p.trim().trim_matches(['"', '\'']).replace('\\', "/").to_ascii_lowercase();
    if raw.starts_with("//./physicaldrive") || raw.starts_with("//./harddisk") || raw.starts_with("//?/globalroot") || (raw.starts_with("//./") && raw.len() == 6 && raw.ends_with(':')) {
        return true;
    }
    if windows_machine_registry(&raw, false) {
        return true;
    }
    let n = win_norm(p);
    let bytes = n.as_bytes();
    if !(bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()) {
        return false;
    }
    let rest = n[2..].trim_start_matches('/');
    if rest.is_empty() {
        return true; // the drive root itself
    }
    // `C:Windows…` (backslashes eaten by the POSIX parser) or `C:/Windows/…`.
    let eaten = raw.len() > 2 && raw.as_bytes()[1] == b':' && raw.as_bytes()[2] != b'/';
    WIN_SYSTEM_DIRS.iter().any(|d| rest == *d || rest.starts_with(&format!("{d}/")) || (eaten && rest.starts_with(d)))
}

/// `HKLM:\…`, `HKEY_LOCAL_MACHINE\…`, `Registry::HKEY_LOCAL_MACHINE\…` (and the other
/// machine-wide hives). `lax`: a `reg.exe` key argument, which always starts with its hive,
/// possibly with the separator eaten by the POSIX parser (`HKLMSOFTWARE…`).
fn windows_machine_registry(lower: &str, lax: bool) -> bool {
    let k = lower.trim_start_matches("microsoft.powershell.core/").trim_start_matches("registry::");
    ["hklm", "hkey_local_machine", "hkcr", "hkey_classes_root", "hku", "hkey_users", "hkcc", "hkey_current_config"].iter().any(|h| k == *h || k.starts_with(&format!("{h}:")) || k.starts_with(&format!("{h}/")) || (lax && k.starts_with(h)))
}

/// Per-user registry keys that start programs or set policy (persistence / lockdown).
/// Compared without separators, so the parser-mangled spelling matches too.
fn windows_sensitive_user_registry(lower: &str) -> bool {
    let k = lower.trim_start_matches("microsoft.powershell.core/").trim_start_matches("microsoft.powershell.core\\").trim_start_matches("registry::");
    let flat: String = k.chars().filter(|c| !matches!(c, '/' | '\\' | ':' | ' ')).collect();
    (flat.starts_with("hkcu") || flat.starts_with("hkey_current_user")) && ["currentversionrun", "winlogon", "policies", "imagefileexecutionoptions", "shellfolders"].iter().any(|s| flat.contains(s))
}

/// The program as written (directory and `.exe` included).
fn argv0(c: &Simple) -> &str {
    c.argv.first().map(String::as_str).unwrap_or("")
}

/// Credential stores of a Windows account (the counterpart of `~/.ssh`, `/etc/shadow`).
pub fn windows_sensitive_path(lower: &str) -> bool {
    let k = lower.replace('\\', "/");
    k.contains("/windows/system32/config/sam") || k.contains("/windows/system32/config/security") || k.contains("/windows/system32/config/system") || k.contains("/microsoft/credentials/") || k.contains("/microsoft/protect/") || k.contains("/microsoft/vault/") || k.ends_with("ntds.dit")
}

/// macOS: `Some(true)` system, `Some(false)` explicitly safe (temp directories, which live
/// under `/var/folders` there), `None` = decide with the Unix rules.
pub fn macos_system_path(p: &str) -> Option<bool> {
    let p = p.trim();
    if !p.starts_with('/') {
        return None;
    }
    let under = |pre: &str| p == pre || p.starts_with(&format!("{pre}/"));
    if ["/var/folders", "/private/var/folders", "/private/tmp", "/tmp"].iter().any(|d| under(d)) {
        return Some(false);
    }
    if ["/System", "/Library", "/private/etc", "/private/var", "/Applications", "/Volumes", "/cores", "/usr/local/Cellar"].iter().any(|d| under(d)) {
        // `/usr/local/Cellar` is Homebrew's: writable by the user on purpose; leave it alone.
        return Some(!under("/usr/local/Cellar"));
    }
    None
}

/// macOS credential stores.
pub fn macos_sensitive_path(lower: &str) -> bool {
    lower.contains("library/keychains/") || lower.ends_with("library/keychains") || lower.contains("/var/db/dslocal/nodes/default/users/")
}

fn flag(c: &Simple, names: &[&str]) -> bool {
    c.argv.iter().skip(1).any(|a| names.iter().any(|n| a.eq_ignore_ascii_case(n)))
}

/// First non-option argument (Windows options start with `/` or `-`), lower-cased.
fn win_sub(c: &Simple) -> String {
    c.argv.iter().skip(1).find(|a| !a.starts_with('-') && !a.starts_with('/')).map(|s| s.to_ascii_lowercase()).unwrap_or_default()
}

/// Value of a PowerShell parameter (`-Scope Process`, `-Scope:Process`).
fn ps_param(c: &Simple, name: &str) -> Option<String> {
    let a = &c.argv;
    for (i, x) in a.iter().enumerate().skip(1) {
        let lx = x.to_ascii_lowercase();
        if lx == name {
            return a.get(i + 1).map(|s| s.to_ascii_lowercase());
        }
        if let Some(v) = lx.strip_prefix(&format!("{name}:")) {
            return Some(v.to_string());
        }
    }
    None
}

/// Arguments that are not options (`-x` / `/x`), as written.
fn win_operands(c: &Simple) -> Vec<&str> {
    c.argv.iter().skip(1).map(String::as_str).filter(|a| !a.starts_with('-') && !(a.starts_with('/') && a.len() <= 24 && !a[1..].contains('/'))).collect()
}

/// Why a Windows command needs an administrator or changes the machine.
pub fn windows_privileged(c: &Simple) -> Option<String> {
    let shown = argv0(c);
    let n = win_name(shown);
    let sub = win_sub(c);
    let any_system = || c.argv.iter().skip(1).any(|a| windows_system_path(a.trim_start_matches("-path:").trim_start_matches("-literalpath:")));
    let r = match n.as_str() {
        "runas" | "gsudo" => format!("`{n}` runs with elevated privileges"),
        "start-process" | "saps" | "start" if ps_param(c, "-verb").is_some_and(|v| v == "runas") => "`Start-Process -Verb RunAs` runs with elevated privileges".into(),
        "reg" if matches!(sub.as_str(), "import" | "restore" | "load" | "unload") => format!("`reg {sub}` rewrites registry hives"),
        "reg" if matches!(sub.as_str(), "add" | "delete" | "copy") => {
            let key = c.argv.iter().skip(2).find(|a| !a.starts_with('/') && !a.starts_with('-')).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
            if windows_machine_registry(&key.replace('\\', "/"), true) || windows_sensitive_user_registry(&key) {
                format!("`reg {sub}` changes system or autostart registry keys")
            } else {
                return None;
            }
        }
        "set-itemproperty" | "sp" | "new-itemproperty" | "remove-itemproperty" | "rp" | "new-item" | "ni" | "set-item" | "si" | "remove-item" | "ri" | "rename-itemproperty"
            if c.argv.iter().skip(1).any(|a| {
                let l = a.to_ascii_lowercase();
                windows_machine_registry(&l.replace('\\', "/"), false) || windows_sensitive_user_registry(&l)
            }) =>
        {
            format!("`{shown}` changes system or autostart registry keys")
        }
        "sc" if matches!(sub.as_str(), "create" | "delete" | "config" | "start" | "stop" | "pause" | "continue" | "failure" | "sdset" | "privs" | "sidtype" | "triggerinfo") => format!("`sc {sub}` changes system services"),
        "new-service" | "set-service" | "stop-service" | "spsv" | "start-service" | "sasv" | "restart-service" | "remove-service" | "suspend-service" | "resume-service" => format!("`{shown}` changes system services"),
        "net" | "net1" if matches!(sub.as_str(), "start" | "stop" | "pause" | "continue") => format!("`net {sub}` changes system services"),
        "net" | "net1" if matches!(sub.as_str(), "user" | "localgroup" | "group" | "accounts") && c.argv.len() > 2 => format!("`net {sub}` changes system accounts"),
        "new-localuser" | "remove-localuser" | "set-localuser" | "disable-localuser" | "enable-localuser" | "add-localgroupmember" | "remove-localgroupmember" | "new-localgroup" | "remove-localgroup" => format!("`{}` changes system accounts", shown),
        "bcdedit" if !c.argv.iter().skip(1).all(|a| matches!(a.to_ascii_lowercase().as_str(), "/enum" | "/v" | "all" | "active" | "firmware" | "bootapp" | "osloader")) => "`bcdedit` changes the boot configuration".into(),
        "bcdboot" | "bootsect" => format!("`{n}` changes the boot configuration"),
        "format" if c.argv.iter().skip(1).any(|a| a.len() == 2 && a.ends_with(':')) => "`format` formats a volume".into(),
        "diskpart" => "`diskpart` changes disks or partitions".into(),
        "format-volume" | "clear-disk" | "initialize-disk" | "new-partition" | "remove-partition" | "resize-partition" | "set-disk" | "set-partition" | "new-volume" | "mount-diskimage" | "dismount-diskimage" => format!("`{}` changes disks or partitions", shown),
        "mountvol" | "subst" if c.argv.len() > 2 => format!("`{n}` changes mounts"),
        "fsutil" if flag(c, &["set", "setzerodata", "setshortname", "setvaliddata", "setflag", "deletejournal", "createjournal", "dismount", "delete", "repair", "initiate", "setdirty"]) => "`fsutil` changes file system settings".into(),
        "takeown" => "`takeown` takes ownership of files".into(),
        "icacls" | "cacls" if flag(c, &["/grant", "/grant:r", "/deny", "/remove", "/remove:g", "/remove:d", "/setowner", "/reset", "/inheritance:e", "/inheritance:d", "/inheritance:r", "/restore", "/setintegritylevel", "/e", "/g", "/r", "/p"]) => format!("`{n}` changes file permissions"),
        "set-acl" if any_system() => "`Set-Acl` changes permissions of a system path".into(),
        "set-executionpolicy" if ps_param(c, "-scope").as_deref() != Some("process") => "`Set-ExecutionPolicy` changes the script execution policy".into(),
        "set-mppreference" | "add-mppreference" | "remove-mppreference" => format!("`{}` changes Windows Defender settings", shown),
        "netsh" if matches!(sub.as_str(), "advfirewall" | "firewall") && flag(c, &["set", "add", "delete", "reset", "import"]) => "`netsh` changes the firewall".into(),
        "netsh" if matches!(sub.as_str(), "interface" | "int" | "winsock" | "winhttp" | "wlan") && flag(c, &["set", "add", "delete", "reset", "import"]) => "`netsh` changes network configuration".into(),
        "new-netfirewallrule" | "set-netfirewallrule" | "remove-netfirewallrule" | "disable-netfirewallrule" | "enable-netfirewallrule" | "set-netfirewallprofile" => format!("`{}` changes the firewall", shown),
        "stop-computer" | "restart-computer" => format!("`{}` changes the machine's power state", shown),
        "schtasks" if flag(c, &["/create", "/delete", "/change"]) => "`schtasks` changes scheduled tasks".into(),
        "register-scheduledtask" | "unregister-scheduledtask" | "set-scheduledtask" => format!("`{}` changes scheduled tasks", shown),
        "vssadmin" if matches!(sub.as_str(), "delete" | "resize" | "create") => "`vssadmin` changes shadow copies (backups)".into(),
        "wbadmin" if matches!(sub.as_str(), "delete" | "start") => "`wbadmin` changes system backups".into(),
        "wevtutil" if matches!(sub.as_str(), "cl" | "clear-log" | "sl" | "set-log" | "im" | "install-manifest" | "um" | "uninstall-manifest") => "`wevtutil` clears or reconfigures event logs".into(),
        "clear-eventlog" | "remove-eventlog" | "limit-eventlog" => format!("`{}` clears or reconfigures event logs", shown),
        "cipher" if flag(c, &["/w", "/e", "/d", "/r", "/k"]) => "`cipher` wipes or re-encrypts files".into(),
        "dism" | "sfc" if !flag(c, &["/?", "/get-help"]) => format!("`{n}` changes the Windows image"),
        "pnputil" | "devcon" if !matches!(sub.as_str(), "enum-devices" | "enum-drivers" | "find" | "status") && !flag(c, &["/enum-devices", "/enum-drivers", "/enum-interfaces"]) => format!("`{n}` changes device drivers"),
        "winget" if matches!(sub.as_str(), "install" | "uninstall" | "remove" | "upgrade" | "update" | "import") && ps_param(c, "--scope").as_deref() != Some("user") => format!("`winget {sub}` modifies system packages"),
        "choco" | "chocolatey" if matches!(sub.as_str(), "install" | "uninstall" | "upgrade" | "update") => format!("`{n} {sub}` modifies system packages"),
        "msiexec" if flag(c, &["/i", "/x", "/a", "/fa", "/package", "/uninstall"]) => "`msiexec` modifies system packages".into(),
        "add-appxprovisionedpackage" | "remove-appxprovisionedpackage" | "install-windowsfeature" | "uninstall-windowsfeature" | "enable-windowsoptionalfeature" | "disable-windowsoptionalfeature" => format!("`{}` modifies system packages", shown),
        // Deleting / overwriting a system location through the Windows spellings.
        "remove-item" | "ri" | "del" | "erase" | "rd" | "rmdir" | "move-item" | "mi" | "move" | "copy-item" | "cpi" | "copy" | "xcopy" | "robocopy" | "set-content" | "add-content" | "ac" | "out-file" | "new-item" | "ni" | "rename-item" | "ren" | "clear-content" | "clc" => {
            let ops = win_operands(c);
            // copy-style commands only write their destination (the last operand).
            let writes = |p: &&str| !matches!(n.as_str(), "copy-item" | "cpi" | "copy" | "xcopy" | "robocopy" | "move-item" | "mi" | "move") || ops.last() == Some(p);
            let p = ops.iter().find(|a| windows_system_path(a) && writes(a))?;
            format!("`{}` modifies system path {p}", shown)
        }
        _ => return None,
    };
    Some(r)
}

/// Why a macOS command needs an administrator or changes the machine.
pub fn macos_privileged(c: &Simple) -> Option<String> {
    let n = c.name();
    let args: Vec<&str> = c.argv.iter().skip(1).map(String::as_str).collect();
    let sub = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");
    let r = match n {
        "launchctl" if matches!(sub, "load" | "unload" | "bootstrap" | "bootout" | "enable" | "disable" | "kickstart" | "kill" | "remove" | "submit" | "start" | "stop" | "config" | "reboot" | "setenv" | "unsetenv" | "limit") => format!("`launchctl {sub}` changes launchd services"),
        "csrutil" if !matches!(sub, "status" | "") => format!("`csrutil {sub}` changes System Integrity Protection"),
        "diskutil" if !matches!(sub, "list" | "info" | "information" | "activity" | "listFilesystems" | "verifyVolume" | "verifyDisk" | "") && !(sub == "apfs" && args.get(1).is_some_and(|s| s.starts_with("list"))) => format!("`diskutil {sub}` changes disks or volumes"),
        "hdiutil" if matches!(sub, "create" | "convert" | "resize" | "burn" | "makehybrid") && args.iter().any(|a| a.starts_with("/dev/")) => "`hdiutil` writes to a device".into(),
        "asr" | "bless" | "fdesetup" | "kmutil" | "kextload" | "kextunload" | "systemextensionsctl" if !matches!(sub, "status" | "list" | "showloaded" | "") => format!("`{n}` changes the boot, encryption or kernel configuration"),
        "nvram" if args.iter().any(|a| a.contains('=') || matches!(*a, "-d" | "-c" | "-f")) => "`nvram` changes firmware variables".into(),
        "spctl" if args.iter().any(|a| matches!(*a, "--master-disable" | "--global-disable" | "--master-enable" | "--global-enable" | "--add" | "--remove" | "--enable" | "--disable" | "--reset-default")) => "`spctl` changes Gatekeeper".into(),
        "systemsetup" if args.iter().any(|a| a.starts_with("-set")) => "`systemsetup` changes system settings".into(),
        "pmset" if args.first().is_some_and(|a| !a.starts_with("-g")) => "`pmset` changes power management".into(),
        "dscl" if args.iter().any(|a| matches!(*a, "-create" | "-delete" | "-passwd" | "-append" | "-merge" | "-change")) => "`dscl` changes system accounts".into(),
        "sysadminctl" | "dseditgroup" | "createhomedir" if !args.is_empty() => format!("`{n}` changes system accounts"),
        "softwareupdate" if args.iter().any(|a| matches!(*a, "-i" | "--install" | "-a" | "--all" | "--schedule" | "--install-rosetta" | "--background")) => "`softwareupdate` installs system updates".into(),
        "installer" if args.contains(&"-pkg") => "`installer` modifies system packages".into(),
        "tmutil" if matches!(sub, "disable" | "delete" | "deletelocalsnapshots" | "thinlocalsnapshots" | "setdestination" | "removedestination" | "disablelocal") => format!("`tmutil {sub}` changes Time Machine backups"),
        "pfctl" if args.iter().any(|a| a.starts_with("-e") || a.starts_with("-d") || a.starts_with("-f") || a.starts_with("-F")) => "`pfctl` changes the firewall".into(),
        "socketfilterfw" if args.iter().any(|a| a.starts_with("--set") || a.starts_with("--add") || a.starts_with("--remove")) => "`socketfilterfw` changes the firewall".into(),
        "scutil" if args.contains(&"--set") => "`scutil --set` changes system names".into(),
        "networksetup" if args.iter().any(|a| a.starts_with("-set") || a.starts_with("-add") || a.starts_with("-remove") || a.starts_with("-create") || a.starts_with("-delete")) => "`networksetup` changes network configuration".into(),
        "defaults" if matches!(sub, "write" | "delete") && args.iter().any(|a| a.starts_with("/Library/")) => "`defaults` changes machine-wide preferences".into(),
        _ => return None,
    };
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(s: &str) -> Simple {
        crate::shell::parse(s).into_iter().next().unwrap_or_else(|| panic!("no command in {s}"))
    }
    fn win(s: &str) -> Option<String> {
        windows_privileged(&cmd(s))
    }
    fn mac(s: &str) -> Option<String> {
        macos_privileged(&cmd(s))
    }

    #[test]
    fn windows_system_paths() {
        for p in ["C:\\Windows\\System32\\drivers\\etc\\hosts", "c:/windows", "C:Windows\\System32", "D:\\", "C:", "C:\\Program Files\\App\\x.dll", "C:\\Program Files (x86)", "%SystemRoot%\\System32", "$env:windir\\x", "\\\\.\\PhysicalDrive0", "\\\\.\\C:", "HKLM:\\SOFTWARE\\Microsoft", "HKEY_LOCAL_MACHINE\\SYSTEM", "Registry::HKEY_LOCAL_MACHINE\\x", "C:\\Users\\u\\..\\..\\Windows\\x", "\\\\?\\C:\\Windows\\x"] {
            assert!(windows_system_path(p), "{p}");
        }
        for p in ["C:\\Users\\u\\project\\src", "D:\\work\\windows-port\\x", "relative\\Windows", "build/windows", "HKCU:\\Software\\App", "NUL", "C:\\Users\\u\\AppData\\Local\\Temp\\x", "/tmp/x"] {
            assert!(!windows_system_path(p), "{p}");
        }
        assert!(windows_sensitive_path(&"C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Credentials\\ABC".to_ascii_lowercase()));
        assert!(windows_sensitive_path(&"c:\\windows\\system32\\config\\SAM".to_ascii_lowercase()));
        assert!(!windows_sensitive_path("c:/users/u/project/readme.md"));
    }

    #[test]
    fn windows_privileged_commands() {
        for c in [
            "reg add HKLM\\SOFTWARE\\X /v y /d 1",
            "reg.exe delete HKEY_LOCAL_MACHINE\\SYSTEM\\X /f",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /d x",
            "reg import evil.reg",
            "sc create svc binPath= C:\\x.exe",
            "sc.exe stop WinDefend",
            "bcdedit /set testsigning on",
            "format D: /q",
            "diskpart /s script.txt",
            "takeown /f C:\\Windows\\System32\\x",
            "icacls C:\\data /grant Everyone:F",
            "Set-ExecutionPolicy Unrestricted",
            "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine",
            "Remove-Item -Recurse -Force C:\\Windows\\Temp2",
            "Remove-Item -Path 'C:\\Program Files\\App' -Recurse",
            "del /s /q C:\\Windows\\x",
            "Set-ItemProperty -Path HKLM:\\SOFTWARE\\X -Name y -Value 1",
            "New-Service -Name x -BinaryPathName C:\\x.exe",
            "Stop-Service WinDefend",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "netsh advfirewall set allprofiles state off",
            "New-NetFirewallRule -DisplayName x -Direction Inbound",
            "Start-Process powershell -Verb RunAs",
            "runas /user:Administrator cmd",
            "vssadmin delete shadows /all /quiet",
            "wevtutil cl Security",
            "schtasks /create /tn x /tr C:\\x.exe /sc onlogon",
            "net user eve P@ss /add",
            "net stop wuauserv",
            "Restart-Computer -Force",
            "winget install Git.Git",
            "msiexec /i app.msi /qn",
            "Copy-Item evil.dll C:\\Windows\\System32\\evil.dll",
            "'C:\\Windows\\System32\\diskpart.exe'",
            "fsutil behavior set disablelastaccess 1",
        ] {
            assert!(win(c).is_some(), "{c}");
        }
        for c in [
            "reg query HKLM\\SOFTWARE\\X",
            "reg add HKCU\\Software\\MyApp /v y /d 1",
            "sc query",
            "bcdedit /enum",
            "icacls C:\\data",
            "Set-ExecutionPolicy Bypass -Scope Process",
            "Remove-Item -Recurse -Force .\\target",
            "Remove-Item C:\\Users\\u\\project\\build -Recurse",
            "del build\\x.obj",
            "Copy-Item C:\\Windows\\System32\\drivers\\etc\\hosts .\\hosts.bak",
            "Get-Service",
            "net view",
            "winget install --scope user Git.Git",
            "winget search git",
            "Get-ItemProperty HKLM:\\SOFTWARE\\X",
            "cargo build --release",
            "format-table",
        ] {
            assert!(win(c).is_none(), "{c}: {:?}", win(c));
        }
        assert_eq!(win_name("C:\\Windows\\System32\\REG.EXE"), "reg");
        assert_eq!(win_name("Remove-Item"), "remove-item");
    }

    #[test]
    fn macos_paths_and_commands() {
        assert_eq!(macos_system_path("/System/Library/x"), Some(true));
        assert_eq!(macos_system_path("/Library/LaunchDaemons/x.plist"), Some(true));
        assert_eq!(macos_system_path("/private/etc/hosts"), Some(true));
        assert_eq!(macos_system_path("/Applications/Evil.app"), Some(true));
        assert_eq!(macos_system_path("/var/folders/ab/T/x"), Some(false), "TMPDIR lives here");
        assert_eq!(macos_system_path("/private/var/folders/ab/T/x"), Some(false));
        assert_eq!(macos_system_path("/private/tmp/x"), Some(false));
        assert_eq!(macos_system_path("/usr/local/Cellar/x"), Some(false));
        assert_eq!(macos_system_path("/Users/u/Library/x"), None);
        assert_eq!(macos_system_path("relative/System"), None);
        assert!(macos_sensitive_path("/users/u/library/keychains/login.keychain-db"));
        for c in ["launchctl load -w /Library/LaunchDaemons/x.plist", "launchctl bootout system/com.x", "csrutil disable", "diskutil eraseDisk APFS X disk2", "diskutil unmountDisk disk2", "nvram boot-args=-v", "spctl --master-disable", "dscl . -create /Users/eve", "sysadminctl -addUser eve", "softwareupdate -i -a", "installer -pkg x.pkg -target /", "tmutil disable", "pmset -a sleep 0", "kextload x.kext", "fdesetup disable", "systemsetup -setremotelogin on"] {
            assert!(mac(c).is_some(), "{c}");
        }
        for c in ["launchctl list", "csrutil status", "diskutil list", "diskutil info disk0", "pmset -g", "spctl --assess x.app", "tmutil listbackups", "dscl . -read /Users/u", "softwareupdate -l", "nvram -p"] {
            assert!(mac(c).is_none(), "{c}: {:?}", mac(c));
        }
    }
}
