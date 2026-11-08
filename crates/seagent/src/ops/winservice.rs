//! Windows Service entry point: `seagent daemon service`, the command line that
//! `seagent service install --system` registers with the Service Control Manager
//! (`sc.exe create SEAgent binPath= "<exe> daemon service" start= auto`).
//!
//! A service process must hand its main thread to `StartServiceCtrlDispatcherW` within 30 s;
//! the dispatcher calls [`service_main`] on a new thread, which reports `SERVICE_RUNNING` and
//! runs the very same daemon loop as `seagent daemon run`. `SERVICE_CONTROL_STOP` / `SHUTDOWN`
//! map to the daemon's stop flag (`Daemon::stop`, what `SIGTERM` does on Unix): running turns
//! are interrupted and saved, then the loop returns and `SERVICE_STOPPED` carries its exit code.
//! A service has no console, so stdout / stderr go to the daemon log first.
//!
//! On every other OS the command explains itself and fails (Unix service managers start
//! `seagent daemon run` directly).

#[cfg(windows)]
mod imp {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, Ordering};
    use std::sync::OnceLock;
    use windows_sys::Win32::System::Services::*;

    const NO_ERROR: u32 = 0;
    const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
    const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;
    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

    struct Hooks {
        name: Vec<u16>,
        daemon: fn() -> i32,
        stop: fn(),
    }

    static HOOKS: OnceLock<Hooks> = OnceLock::new();
    static STATUS: AtomicIsize = AtomicIsize::new(0);
    static EXIT: AtomicI32 = AtomicI32::new(0);
    static STOPPING: AtomicBool = AtomicBool::new(false);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn report(state: u32, exit: i32, wait_ms: u32) {
        let h = STATUS.load(Ordering::SeqCst);
        if h == 0 {
            return;
        }
        static CHECKPOINT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
        let st = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 },
            dwWin32ExitCode: if exit == 0 { NO_ERROR } else { ERROR_SERVICE_SPECIFIC_ERROR },
            dwServiceSpecificExitCode: exit as u32,
            dwCheckPoint: if pending { CHECKPOINT.fetch_add(1, Ordering::SeqCst) + 1 } else { 0 },
            dwWaitHint: wait_ms,
        };
        // SAFETY: `h` came from RegisterServiceCtrlHandlerExW; `st` is a valid struct.
        unsafe { SetServiceStatus(h, &st) };
    }

    /// Stop requests can land while the daemon is still starting (its loop clears the flag
    /// when it begins), so the request is repeated until the process ends.
    fn request_stop() {
        if STOPPING.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(h) = HOOKS.get() else { return };
        let stop = h.stop;
        std::thread::spawn(move || loop {
            stop();
            std::thread::sleep(std::time::Duration::from_millis(250));
        });
    }

    unsafe extern "system" fn handler(control: u32, _event: u32, _data: *mut core::ffi::c_void, _ctx: *mut core::ffi::c_void) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                report(SERVICE_STOP_PENDING, 0, 35_000);
                request_stop();
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
        let Some(h) = HOOKS.get() else { return };
        let status = RegisterServiceCtrlHandlerExW(h.name.as_ptr(), Some(handler), std::ptr::null_mut());
        if status == 0 {
            return;
        }
        STATUS.store(status, Ordering::SeqCst);
        report(SERVICE_START_PENDING, 0, 30_000);
        report(SERVICE_RUNNING, 0, 0);
        let code = (h.daemon)();
        EXIT.store(code, Ordering::SeqCst);
        report(SERVICE_STOPPED, code, 0);
    }

    /// Send this process's stdout and stderr to `log` (appending): a service has no console.
    fn redirect_output(log: &Path) {
        use std::os::windows::io::IntoRawHandle;
        use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
        if let Some(d) = log.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(log) else { return };
        let Ok(f2) = f.try_clone() else { return };
        // SAFETY: the handles are leaked on purpose: they stay the std handles for the
        // lifetime of the process.
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE, f.into_raw_handle() as isize);
            SetStdHandle(STD_ERROR_HANDLE, f2.into_raw_handle() as isize);
        }
    }

    pub fn run(name: &str, log: &Path, daemon: fn() -> i32, stop: fn()) -> Result<i32, String> {
        if HOOKS.set(Hooks { name: wide(name), daemon, stop }).is_err() {
            return Err("the service dispatcher is already running".into());
        }
        let h = HOOKS.get().expect("set above");
        let table = [
            SERVICE_TABLE_ENTRYW { lpServiceName: h.name.as_ptr() as *mut u16, lpServiceProc: Some(service_main) },
            SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None },
        ];
        // Only redirect once we know the SCM started us (a console user keeps their output).
        let interactive = std::io::IsTerminal::is_terminal(&std::io::stderr());
        if !interactive {
            redirect_output(log);
        }
        // SAFETY: `table` is NUL-terminated and outlives the call, which returns when the
        // service has stopped.
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                "`seagent daemon service` is the Windows Service entry point and only runs under the Service Control Manager; install it with `seagent service install --system` (elevated), or run `seagent daemon run` in a console".to_string()
            } else {
                format!("StartServiceCtrlDispatcherW: {e}")
            });
        }
        Ok(EXIT.load(Ordering::SeqCst))
    }
}

/// Run `daemon` as the Windows Service `name` (see the module docs); `stop` is the daemon's
/// stop flag. Returns the daemon's exit code once the service has stopped.
#[cfg(windows)]
pub fn run(name: &str, log: &std::path::Path, daemon: fn() -> i32, stop: fn()) -> Result<i32, String> {
    imp::run(name, log, daemon, stop)
}

#[cfg(not(windows))]
pub fn run(_name: &str, _log: &std::path::Path, _daemon: fn() -> i32, _stop: fn()) -> Result<i32, String> {
    Err("`seagent daemon service` is the Windows Service entry point; on this system the service manager runs `seagent daemon run` (see `seagent service install`)".into())
}
