//! `launch::launch` against stand-in browsers that behave like the ones that broke it:
//!
//! * Edge on Windows relaunches itself when it inherits an AppCompat layer
//!   (`__COMPAT_LAYER=DetectorsAppHealth`, set on everything started from Explorer, so the
//!   desktop app and its daemon carry it): the process seagent started exits 0 within ~130 ms
//!   and the real browser keeps running under another pid. `browser start` used to report
//!   "exited (exit code: 0) before DevTools was ready" and leave that browser behind.
//! * the variable itself must never reach the browser (Windows).
//! * a launcher that exits non-zero is still an error, and `browser doctor` reports it.
//!
//! Every OS runs the same cases: Linux / macOS with a `sh` stand-in, Windows with a `.cmd`
//! that runs a PowerShell script through a copy of `powershell.exe` named `chrome.exe`, so the
//! process listing sees a Chromium-family process on the profile, as with the real thing.

use crate::launch::{launch, LaunchOpts};
use seagent_core::proc::PidGuard;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Kills the stand-in's processes (the launcher's group and the relaunched browser) on drop.
struct Kill(Vec<PidGuard>);

impl Drop for Kill {
    fn drop(&mut self) {
        self.0.clear();
    }
}

fn pid_in(udd: &Path, name: &str) -> Option<i32> {
    std::fs::read_to_string(udd.join(name)).ok()?.trim().parse().ok()
}

/// A stand-in browser. It prints `compat=<__COMPAT_LAYER>`; with `SEAGENT_FAKE_RELAUNCH` set
/// (and no `--relaunched`) it starts a detached copy of itself and exits 0 at once, like Edge;
/// otherwise it records its pid (`browser.pid`, plus `SingletonLock` on Unix), writes
/// `DevToolsActivePort` 1.5 s later and sleeps. `SEAGENT_FAKE_FAIL` makes it print an error and
/// exit 3.
#[cfg(unix)]
fn fake(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let exe = dir.join("fake-browser");
    let script = r#"#!/bin/sh
for a in "$@"; do case "$a" in --user-data-dir=*) d="${a#*=}";; --relaunched) r=1;; esac; done
echo "compat=$__COMPAT_LAYER"
if [ -n "$SEAGENT_FAKE_FAIL" ]; then echo "boom: cannot use the profile directory"; exit 3; fi
if [ -n "$SEAGENT_FAKE_RELAUNCH" ] && [ -z "$r" ]; then echo $$ > "$d/launcher.pid"; "$0" "$@" --relaunched & exit 0; fi
echo $$ > "$d/browser.pid"
ln -sf "host-$$" "$d/SingletonLock"
sleep 1.5
printf '9\n/devtools/browser/fake\n' > "$d/DevToolsActivePort"
exec sleep 20
"#;
    std::fs::write(&exe, script).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    exe
}

#[cfg(windows)]
fn fake(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let host = bin.join("chrome.exe");
    let system = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    std::fs::copy(system.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"), &host).unwrap();
    let ps = dir.join("fake-browser.ps1");
    let script = format!(
        r#"$d = ($args | Where-Object {{ $_ -like '--user-data-dir=*' }} | Select-Object -First 1).Substring(16)
"compat=$env:__COMPAT_LAYER"
if ($env:SEAGENT_FAKE_FAIL) {{ "boom: cannot use the profile directory"; exit 3 }}
if ($env:SEAGENT_FAKE_RELAUNCH -and -not ($args -contains '--relaunched')) {{
  [IO.File]::WriteAllText((Join-Path $d 'launcher.pid'), "$PID")
  Start-Process -FilePath '{host}' -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '{ps}') + @($args) + '--relaunched') -WindowStyle Hidden
  exit 0
}}
[IO.File]::WriteAllText((Join-Path $d 'browser.pid'), "$PID")
Start-Sleep -Milliseconds 1500
[IO.File]::WriteAllText((Join-Path $d 'DevToolsActivePort'), "9`n/devtools/browser/fake`n")
Start-Sleep 20
"#,
        host = host.display(),
        ps = ps.display()
    );
    std::fs::write(&ps, script).unwrap();
    let exe = dir.join("fake-browser.cmd");
    std::fs::write(&exe, format!("@\"{}\" -NoProfile -ExecutionPolicy Bypass -File \"{}\" %*\r\n", host.display(), ps.display())).unwrap();
    exe
}

fn opts<'a>(exe: &'a Path, udd: &'a Path, env: &[(&str, &str)]) -> LaunchOpts<'a> {
    LaunchOpts { exe, user_data_dir: udd, headless: true, no_sandbox: false, extra_args: &[], port: 0, managed: true, env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
}

/// What the Edge relaunch looks like to seagent: the started process exits 0 before DevTools is
/// up and another process on the same profile announces it. The launch waits for that one and
/// owns it by its pid.
#[test]
fn a_launcher_that_exits_0_and_relaunches_is_followed() {
    let _s = crate::tests::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-relaunch");
    let exe = fake(dir.path());
    let udd = dir.path().join("profile");
    let mut kill = Kill(vec![]);
    let t0 = Instant::now();
    let r = launch(&opts(&exe, &udd, &[("SEAGENT_FAKE_RELAUNCH", "1")]), Duration::from_secs(40));
    kill.0.extend(["launcher.pid", "browser.pid"].iter().filter_map(|f| pid_in(&udd, f)).map(PidGuard));
    let l = r.unwrap_or_else(|e| panic!("the relaunched browser was not followed: {e}"));
    assert!(pid_in(&udd, "launcher.pid").is_some(), "the stand-in did relaunch itself");
    assert_eq!(l.ws, "ws://127.0.0.1:9/devtools/browser/fake");
    assert_eq!(Some(l.pid), pid_in(&udd, "browser.pid"), "the browser that really runs is the one seagent owns");
    assert!(l.owned);
    assert!(t0.elapsed() < crate::launch::HANDOFF_GRACE + Duration::from_secs(10), "{:?}", t0.elapsed());
    assert_eq!(crate::launch::last_failure(), None);
}

/// Windows: `__COMPAT_LAYER` (inherited, or in the launch environment) never reaches the
/// browser; Edge also gets `--edge-skip-compat-layer-relaunch`. Elsewhere the environment is
/// passed through unchanged and no flag is added.
#[test]
fn the_appcompat_layer_never_reaches_the_browser_on_windows() {
    let _s = crate::tests::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-compat");
    let exe = fake(dir.path());
    let udd = dir.path().join("profile");
    let mut kill = Kill(vec![]);
    let r = launch(&opts(&exe, &udd, &[("__COMPAT_LAYER", "DetectorsAppHealth")]), Duration::from_secs(40));
    kill.0.extend(pid_in(&udd, "browser.pid").map(PidGuard));
    let l = r.unwrap_or_else(|e| panic!("{e}"));
    kill.0.push(PidGuard(l.pid));
    let log = std::fs::read_to_string(udd.join("seagent-browser.log")).unwrap();
    let seen = log.lines().find_map(|x| x.trim().strip_prefix("compat=")).map(str::to_string);
    if cfg!(windows) {
        assert_eq!(seen.as_deref(), Some(""), "the browser saw an AppCompat layer: {log}");
    } else {
        assert_eq!(seen.as_deref(), Some("DetectorsAppHealth"), "Linux / macOS pass the environment through unchanged: {log}");
    }
    let edge = Path::new(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");
    let args = crate::launch::chrome_args(&opts(edge, &udd, &[]));
    assert_eq!(args.iter().any(|a| a == "--edge-skip-compat-layer-relaunch"), cfg!(windows), "{args:?}");
    assert_eq!(args.last().map(String::as_str), Some("about:blank"), "the start page stays last");
    let chrome = Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe");
    assert!(!crate::launch::chrome_args(&opts(chrome, &udd, &[])).iter().any(|a| a.contains("compat-layer")));
}

/// A launcher that fails (non-zero exit) is still an error at once, with the browser's own
/// output, and `browser doctor` names it as the last start's failure.
#[test]
fn a_failed_start_is_reported_with_its_output_and_by_doctor() {
    let _s = crate::tests::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-failstart");
    let exe = fake(dir.path());
    let udd = dir.path().join("profile");
    let t0 = Instant::now();
    let e = match launch(&opts(&exe, &udd, &[("SEAGENT_FAKE_FAIL", "1")]), Duration::from_secs(40)) {
        Ok(l) => {
            let _k = PidGuard(l.pid);
            panic!("a launcher exiting 3 was taken for a browser");
        }
        Err(e) => e,
    };
    assert!(e.contains("exited") && e.contains("boom: cannot use the profile directory"), "{e}");
    assert!(t0.elapsed() < Duration::from_secs(20), "a failure is reported without waiting out the hand-off grace: {:?}", t0.elapsed());
    assert_eq!(crate::launch::last_failure().as_deref(), Some(e.as_str()));
    let cfg = crate::config::BrowserConfig { backend: "local".into(), enabled: toml::Value::Boolean(true), executable: exe.display().to_string(), default_profile: format!("failstart{}", std::process::id()), ..Default::default() };
    let c = crate::tests::ctx("failstart", "sess-failstart");
    let o = crate::tests::tool(&cfg, "browser").call(&c, serde_json::json!({"action": "doctor"}));
    let v: serde_json::Value = serde_json::from_str(&o.content).unwrap_or_else(|_| panic!("doctor JSON: {}", o.content));
    let last = v["checks"].as_array().unwrap().iter().find(|c| c["id"] == "last-start").unwrap_or_else(|| panic!("no last-start check: {v}"));
    assert_eq!(last["status"], "fail");
    assert!(last["summary"].as_str().unwrap().contains("boom"), "{last}");
    assert!(last["fixHint"].as_str().unwrap().contains("seagent-browser.log"), "{last}");
    assert_eq!(v["ok"], false);
}

/// "A browser holds this profile": Windows reads it from `lockfile` (Chromium keeps it open
/// without write sharing while it runs), Linux / macOS from the `SingletonLock` pid.
#[test]
fn profile_in_use_follows_the_platform_lock() {
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-lock");
    let udd = dir.path().join("p");
    std::fs::create_dir_all(&udd).unwrap();
    assert!(!crate::launch::profile_in_use(&udd), "no lock at all");
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        let held = std::fs::OpenOptions::new().write(true).create(true).truncate(true).share_mode(FILE_SHARE_READ).open(udd.join("lockfile")).unwrap();
        assert!(crate::launch::profile_in_use(&udd), "a held lockfile means a running browser");
        drop(held);
        assert!(!crate::launch::profile_in_use(&udd), "a lockfile left by a crashed browser does not");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(format!("host-{}", std::process::id()), udd.join("SingletonLock")).unwrap();
        assert!(crate::launch::profile_in_use(&udd), "a live SingletonLock pid means a running browser");
        std::fs::remove_file(udd.join("SingletonLock")).unwrap();
        std::os::unix::fs::symlink("host-2147483646", udd.join("SingletonLock")).unwrap();
        assert!(!crate::launch::profile_in_use(&udd), "a dead pid does not");
    }
}

/// Only directories seagent made for its own browser are ever closed to free them.
#[test]
fn only_seagent_profile_dirs_count_as_its_own() {
    let home = Path::new("data").join("browser");
    assert!(crate::launch::own_profile_dir(&home.join("profiles").join("seagent")));
    assert!(crate::launch::own_profile_dir(&home.join("real-profile").join("chrome")));
    assert!(!crate::launch::own_profile_dir(Path::new("Google").join("Chrome").join("User Data").as_path()));
    assert!(!crate::launch::own_profile_dir(&Path::new("x").join("profiles").join("seagent")));
}

/// Windows, the real thing: the host's own Edge / Chrome (`find_executable`'s order) started
/// the way `browser start` starts the managed profile, while seagent carries the AppCompat
/// layer Explorer gives the desktop app and its daemon. Before the fix Edge's launcher exited 0
/// in ~100 ms ("exited (exit code: 0) before DevTools was ready"); now the browser comes up,
/// its DevTools answers, and the pid seagent owns is the browser holding the profile. Skipped
/// (with a note) on a host with no Chromium-family browser.
#[cfg(windows)]
#[test]
fn the_host_browser_starts_with_an_inherited_appcompat_layer() {
    let _s = crate::tests::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let exe = match crate::launch::find_executable("") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: no Chromium-family browser on this host ({e})");
            return;
        }
    };
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-realhost");
    let udd = dir.path().join("browser").join("profiles").join("seagent");
    let mut kill = Kill(vec![]);
    let o = opts(&exe, &udd, &[("__COMPAT_LAYER", "DetectorsAppHealth")]);
    let t0 = Instant::now();
    let l = launch(&o, Duration::from_secs(60)).unwrap_or_else(|e| panic!("{} did not start: {e}", exe.display()));
    kill.0.push(PidGuard(l.pid));
    eprintln!("{} ({}) up in {:?}: {}", exe.display(), crate::launch::kind_of(&exe), t0.elapsed(), l.ws);
    let v = crate::cdp::get_json(&l.http, "/json/version", None, Duration::from_secs(10)).expect("its DevTools answers");
    assert!(v["Browser"].as_str().is_some_and(|b| !b.is_empty()), "{v}");
    assert!(l.owned && crate::util::pid_alive(l.pid), "seagent owns a live browser process");
    assert!(crate::launch::profile_in_use(&udd), "the browser holds seagent's own profile");
    // A second start on the same profile reuses that browser instead of handing off to it.
    let again = launch(&o, Duration::from_secs(20)).expect("a second start reuses the running browser");
    assert_eq!(again.ws, l.ws);
    assert_eq!(crate::launch::last_failure(), None);
    drop(kill);
    let until = Instant::now() + Duration::from_secs(15);
    while crate::launch::profile_in_use(&udd) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200));
    }
}
