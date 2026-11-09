//! Locale-independent Windows reads for `cis-windows`: `net accounts`, `net user`, `netsh` and
//! `auditpol` translate their labels, so those checks call the APIs behind them in-process
//! and print fixed English `key=value` lines. All of them are read-only and work without
//! elevation, except the audit policy (`AuditQuerySystemPolicy` needs an elevated token; the
//! check is then `skip`).
//!
//! | argv | API | output |
//! |---|---|---|
//! | `seagent:account-policy` | `NetUserModalsGet` 0 + 3 | `min_password_length`, `password_history`, `max_password_age_days` (`unlimited`), `min_password_age_days`, `lockout_threshold`, `lockout_duration_minutes`, `lockout_window_minutes` |
//! | `seagent:local-user <rid>` | `NetUserEnum` 20 | `name`, `disabled=yes\|no` (by RID: Guest is 501 on every display language) |
//! | `seagent:firewall` | registry (Group Policy over the local setting) | `domain`, `private`, `public` = `on\|off\|unset` |
//! | `seagent:service <name>` | `QueryServiceStatus` / `QueryServiceConfigW` | `state`, `start`; exit 1060 when absent |
//! | `seagent:audit <subcategory GUID>` | `AuditQuerySystemPolicy` | `success=yes\|no`, `failure=yes\|no` |

/// The probe names a check may use.
pub const PROBES: &[&str] = &["seagent:account-policy", "seagent:local-user", "seagent:firewall", "seagent:service", "seagent:audit"];

/// Is `argv` a well-formed probe call?
pub fn allowed(argv: &[String]) -> bool {
    match (argv.first().map(String::as_str), argv.len()) {
        (Some("seagent:account-policy" | "seagent:firewall"), 1) => true,
        (Some("seagent:local-user"), 2) => argv[1].parse::<u32>().is_ok(),
        (Some("seagent:service"), 2) => !argv[1].is_empty() && argv[1].chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        (Some("seagent:audit"), 2) => parse_guid(&argv[1]).is_some(),
        _ => false,
    }
}

/// `{0CCE9215-69AE-11D9-BED3-505054503030}` (braces optional) as a 128-bit value.
pub fn parse_guid(s: &str) -> Option<u128> {
    let t = s.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = t.split('-').collect();
    if parts.iter().map(|p| p.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12] {
        return None;
    }
    u128::from_str_radix(&parts.concat(), 16).ok()
}

/// Seconds as whole days / minutes; `u32::MAX` (TIMEQ_FOREVER) is `unlimited`.
pub fn span(secs: u32, unit: u32) -> String {
    if secs == u32::MAX { "unlimited".into() } else { (secs / unit).to_string() }
}

/// The effective firewall state of one profile: the Group Policy value wins over the local one.
pub fn firewall_state(policy: Option<u32>, local: Option<u32>) -> &'static str {
    match policy.or(local) {
        Some(0) => "off",
        Some(_) => "on",
        None => "unset",
    }
}

/// Run a probe: `(exit code, output)` like an external command.
pub fn run(argv: &[String]) -> (Option<i32>, String) {
    #[cfg(windows)]
    {
        let r = match argv[0].as_str() {
            "seagent:account-policy" => win::account_policy(),
            "seagent:local-user" => win::local_user(argv[1].parse().unwrap_or(0)),
            "seagent:firewall" => Ok(win::firewall()),
            "seagent:service" => win::service(&argv[1]),
            "seagent:audit" => win::audit(parse_guid(&argv[1]).unwrap_or(0)),
            p => Err((1, format!("unknown probe {p}"))),
        };
        match r {
            Ok(s) => (Some(0), s),
            Err((code, e)) => (Some(code as i32), e),
        }
    }
    #[cfg(not(windows))]
    (None, format!("{} reads Windows APIs; not available on this system", argv.first().map(String::as_str).unwrap_or("")))
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, NetUserEnum, NetUserModalsGet, FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, UF_ACCOUNTDISABLE, USER_INFO_20, USER_MODALS_INFO_0, USER_MODALS_INFO_3};
    use windows_sys::Win32::Security::Authentication::Identity::{AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION, POLICY_AUDIT_EVENT_FAILURE, POLICY_AUDIT_EVENT_SUCCESS};
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
    use windows_sys::Win32::System::Services::{CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatus, QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_STATUS};

    type R = Result<String, (u32, String)>;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn last_error() -> u32 {
        // SAFETY: reads this thread's last-error value.
        unsafe { windows_sys::Win32::Foundation::GetLastError() }
    }

    /// SAFETY: `p` is null or a NUL-terminated UTF-16 string.
    unsafe fn from_wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    pub fn account_policy() -> R {
        let (mut b0, mut b3) = (std::ptr::null_mut::<u8>(), std::ptr::null_mut::<u8>());
        // SAFETY: NetUserModalsGet allocates the buffers; both are read as their level's struct
        // and freed with NetApiBufferFree.
        unsafe {
            let e = NetUserModalsGet(std::ptr::null(), 0, &mut b0);
            if e != 0 {
                return Err((e, format!("NetUserModalsGet level 0 failed ({e})")));
            }
            let m0 = *(b0 as *const USER_MODALS_INFO_0);
            NetApiBufferFree(b0 as _);
            let e = NetUserModalsGet(std::ptr::null(), 3, &mut b3);
            if e != 0 {
                return Err((e, format!("NetUserModalsGet level 3 failed ({e})")));
            }
            let m3 = *(b3 as *const USER_MODALS_INFO_3);
            NetApiBufferFree(b3 as _);
            Ok(format!(
                "min_password_length={}\npassword_history={}\nmax_password_age_days={}\nmin_password_age_days={}\nlockout_threshold={}\nlockout_duration_minutes={}\nlockout_window_minutes={}\n",
                m0.usrmod0_min_passwd_len,
                m0.usrmod0_password_hist_len,
                super::span(m0.usrmod0_max_passwd_age, 86_400),
                super::span(m0.usrmod0_min_passwd_age, 86_400),
                m3.usrmod3_lockout_threshold,
                super::span(m3.usrmod3_lockout_duration, 60),
                super::span(m3.usrmod3_lockout_observation_window, 60)
            ))
        }
    }

    pub fn local_user(rid: u32) -> R {
        let mut buf = std::ptr::null_mut::<u8>();
        let (mut read, mut total, mut resume) = (0u32, 0u32, 0u32);
        // SAFETY: one MAX_PREFERRED_LENGTH call returns every local account as USER_INFO_20
        // records in one NetApi buffer, freed below.
        unsafe {
            let e = NetUserEnum(std::ptr::null(), 20, FILTER_NORMAL_ACCOUNT, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, &mut resume);
            if e != 0 {
                return Err((e, format!("NetUserEnum failed ({e})")));
            }
            let users = std::slice::from_raw_parts(buf as *const USER_INFO_20, read as usize);
            let found = users.iter().find(|u| u.usri20_user_id == rid).map(|u| (from_wide(u.usri20_name), u.usri20_flags & UF_ACCOUNTDISABLE != 0));
            NetApiBufferFree(buf as _);
            match found {
                Some((name, disabled)) => Ok(format!("name={name}\nrid={rid}\ndisabled={}\n", if disabled { "yes" } else { "no" })),
                None => Err((2, format!("no local account with RID {rid}"))),
            }
        }
    }

    fn dword(key: &str, value: &str) -> Option<u32> {
        let (k, v) = (wide(key), wide(value));
        let (mut data, mut size) = (0u32, 4u32);
        // SAFETY: a DWORD read into a 4-byte buffer.
        let e = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), &mut data as *mut u32 as _, &mut size) };
        (e == 0).then_some(data)
    }

    pub fn firewall() -> String {
        [("domain", "DomainProfile"), ("private", "StandardProfile"), ("public", "PublicProfile")]
            .iter()
            .map(|(name, key)| {
                let policy = dword(&format!("SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\{key}"), "EnableFirewall");
                let local = dword(&format!("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\{key}"), "EnableFirewall");
                format!("{name}={}\n", super::firewall_state(policy, local))
            })
            .collect()
    }

    pub fn service(name: &str) -> R {
        let n = wide(name);
        // SAFETY: query-only handles, closed on every path; the config buffer is 8 KiB and
        // 8-byte aligned (the struct holds pointers).
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm == 0 {
                let e = last_error();
                return Err((e, format!("OpenSCManager failed ({e})")));
            }
            let svc = OpenServiceW(scm, n.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
            if svc == 0 {
                let e = last_error();
                CloseServiceHandle(scm);
                return Err((e, if e == 1060 { format!("service {name} does not exist") } else { format!("cannot open service {name} ({e})") }));
            }
            let mut st: SERVICE_STATUS = std::mem::zeroed();
            let state = if QueryServiceStatus(svc, &mut st) != 0 { state_name(st.dwCurrentState) } else { "unknown" };
            let mut buf = vec![0u64; 1024];
            let mut need = 0u32;
            let start = if QueryServiceConfigW(svc, buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW, 8192, &mut need) != 0 { start_name((*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW)).dwStartType) } else { "unknown" };
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            Ok(format!("name={name}\nstate={state}\nstart={start}\n"))
        }
    }

    fn state_name(s: u32) -> &'static str {
        match s {
            1 => "stopped",
            2 => "start_pending",
            3 => "stop_pending",
            4 => "running",
            5 => "continue_pending",
            6 => "pause_pending",
            7 => "paused",
            _ => "unknown",
        }
    }

    fn start_name(s: u32) -> &'static str {
        match s {
            0 => "boot",
            1 => "system",
            2 => "auto",
            3 => "demand",
            4 => "disabled",
            _ => "unknown",
        }
    }

    pub fn audit(guid: u128) -> R {
        let g = windows_sys::core::GUID::from_u128(guid);
        let mut p = std::ptr::null_mut::<AUDIT_POLICY_INFORMATION>();
        // SAFETY: one subcategory in, one record out, freed with AuditFree.
        unsafe {
            if AuditQuerySystemPolicy(&g, 1, &mut p) == 0 {
                let e = last_error();
                return Err((e, if e == 5 { "reading the audit policy needs an elevated prompt (access denied)".into() } else { format!("AuditQuerySystemPolicy failed ({e})") }));
            }
            let info = (*p).AuditingInformation;
            AuditFree(p as _);
            let yn = |f: i32| if info & f as u32 != 0 { "yes" } else { "no" };
            Ok(format!("success={}\nfailure={}\n", yn(POLICY_AUDIT_EVENT_SUCCESS), yn(POLICY_AUDIT_EVENT_FAILURE)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_shapes_and_helpers() {
        let a = |v: &[&str]| allowed(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(a(&["seagent:account-policy"]) && a(&["seagent:firewall"]) && a(&["seagent:local-user", "501"]) && a(&["seagent:service", "WinDefend"]));
        assert!(a(&["seagent:audit", "{0CCE9215-69AE-11D9-BED3-505054503030}"]));
        assert!(!a(&["seagent:account-policy", "x"]) && !a(&["seagent:local-user", "Guest"]) && !a(&["seagent:service", "a b"]) && !a(&["seagent:audit", "nope"]) && !a(&["seagent:other"]));
        assert_eq!(parse_guid("0cce9215-69ae-11d9-bed3-505054503030"), Some(0x0CCE9215_69AE_11D9_BED3_505054503030));
        assert_eq!((span(u32::MAX, 86_400), span(42 * 86_400, 86_400), span(1800, 60)), ("unlimited".into(), "42".into(), "30".into()));
        assert_eq!((firewall_state(Some(1), Some(0)), firewall_state(None, Some(0)), firewall_state(Some(0), None), firewall_state(None, None)), ("on", "off", "off", "unset"));
        assert!(PROBES.iter().all(|p| p.starts_with("seagent:")));
    }

    /// The real APIs on this machine: every key the checklist reads is printed.
    #[cfg(windows)]
    #[test]
    fn probes_read_this_windows_host() {
        let r = |v: &[&str]| run(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let (code, out) = r(&["seagent:account-policy"]);
        assert_eq!(code, Some(0), "{out}");
        for k in ["min_password_length=", "password_history=", "max_password_age_days=", "lockout_threshold=", "lockout_duration_minutes="] {
            assert!(out.lines().any(|l| l.starts_with(k)), "{k} missing: {out}");
        }
        let (code, out) = r(&["seagent:local-user", "501"]);
        assert_eq!(code, Some(0), "{out}");
        assert!(out.contains("rid=501\n") && (out.contains("disabled=yes") || out.contains("disabled=no")), "{out}");
        let (_, out) = r(&["seagent:firewall"]);
        assert_eq!(out.lines().map(|l| l.split('=').next().unwrap_or("")).collect::<Vec<_>>(), ["domain", "private", "public"], "{out}");
        let (code, out) = r(&["seagent:service", "EventLog"]);
        assert_eq!(code, Some(0), "{out}");
        assert!(out.contains("state=running") && out.contains("start=auto"), "{out}");
        assert_eq!(r(&["seagent:service", "NoSuchServiceSeagent"]).0, Some(1060));
        let (code, out) = r(&["seagent:audit", "{0CCE9215-69AE-11D9-BED3-505054503030}"]);
        assert!(code == Some(0) && out.contains("success=") || code == Some(5) || code == Some(1314), "{code:?} {out}");
    }
}
