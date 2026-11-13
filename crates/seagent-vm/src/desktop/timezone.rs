//! The guest desktop's time zone (`desktop_vm.timezone`, default `host`): an IANA name the guest
//! links to `/etc/localtime` at every boot (SMBIOS OEM string `seagent-tz=…`, read by
//! `seagent-display-setup`), so the clock in the VM and the pages its Chromium opens show the
//! same local time as the host. Windows names its zones differently (`Taipei Standard Time`):
//! those are mapped with CLDR's table, and a zone missing from it falls back to the host's
//! current UTC offset (`Etc/GMT-8`).

/// An IANA zone name that is safe on a QEMU command line and in the guest's shell (no `,`,
/// spaces, quotes or `..`): `Asia/Taipei`, `Etc/GMT-8`, `UTC`.
pub fn valid_tz(tz: &str) -> bool {
    !tz.is_empty() && tz.len() <= 64 && !tz.contains("..") && !tz.starts_with('/') && tz.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'-'))
}

/// What the guest is told for a `desktop_vm.timezone` setting: `host` → the host's zone (None
/// when it cannot be told), `""` → nothing (the image's UTC), otherwise the name itself.
pub fn resolve(setting: &str) -> Option<String> {
    match setting {
        "" => None,
        "host" => host(),
        tz => Some(tz.to_string()),
    }
}

/// The host's IANA time zone.
#[cfg(not(windows))]
pub fn host() -> Option<String> {
    from_unix(std::env::var("TZ").ok().as_deref(), std::fs::read_link("/etc/localtime").ok().as_deref(), std::fs::read_to_string("/etc/timezone").ok().as_deref())
}

/// `TZ` (`Asia/Taipei`, `:Asia/Taipei` or a zoneinfo path), else the `/etc/localtime` symlink
/// (Linux `/usr/share/zoneinfo/…`, macOS `/var/db/timezone/zoneinfo/…`), else `/etc/timezone`.
#[cfg_attr(windows, allow(dead_code))]
fn from_unix(tz_env: Option<&str>, localtime: Option<&std::path::Path>, etc_timezone: Option<&str>) -> Option<String> {
    let zone_of = |s: &str| -> Option<String> {
        let s = s.trim().trim_start_matches(':');
        let s = s.rfind("zoneinfo/").map_or(s, |i| &s[i + "zoneinfo/".len()..]);
        // A POSIX rule (`CST-8`) is not a zone name; only Area/City and the UTC aliases are.
        (valid_tz(s) && (s.contains('/') || matches!(s, "UTC" | "GMT"))).then(|| s.to_string())
    };
    tz_env.and_then(zone_of).or_else(|| localtime.and_then(|p| zone_of(&p.to_string_lossy()))).or_else(|| etc_timezone.and_then(zone_of))
}

#[cfg(windows)]
pub fn host() -> Option<String> {
    const KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation";
    from_windows(reg_sz(KEY, "TimeZoneKeyName").as_deref(), reg_dword(KEY, "ActiveTimeBias").map(|b| b as i32))
}

/// A Windows zone id (+ the current bias, minutes with UTC = local + bias) as an IANA name.
#[cfg_attr(not(windows), allow(dead_code))]
fn from_windows(key_name: Option<&str>, active_bias: Option<i32>) -> Option<String> {
    if let Some(iana) = key_name.and_then(|k| WINDOWS_ZONES.iter().find(|(w, _)| *w == k.trim())).map(|(_, i)| *i) {
        return Some(iana.to_string());
    }
    // Unknown zone: its current offset, when it is whole hours (Etc/GMT signs are inverted).
    let bias = active_bias?;
    if bias % 60 != 0 || !(-14 * 60..=12 * 60).contains(&bias) {
        return None;
    }
    let h = bias / 60;
    Some(if h == 0 { "Etc/UTC".into() } else { format!("Etc/GMT{h:+}") })
}

#[cfg(windows)]
fn reg_sz(key: &str, value: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let k: Vec<u16> = key.encode_utf16().chain([0]).collect();
    let v: Vec<u16> = value.encode_utf16().chain([0]).collect();
    let mut buf = [0u16; 256];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: NUL-terminated key/value names; `len` is the buffer size in bytes.
    let rc = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) };
    (rc == 0).then(|| String::from_utf16_lossy(&buf[..(len as usize / 2).min(buf.len())]).trim_end_matches('\0').to_string())
}

#[cfg(windows)]
fn reg_dword(key: &str, value: &str) -> Option<u32> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
    let k: Vec<u16> = key.encode_utf16().chain([0]).collect();
    let v: Vec<u16> = value.encode_utf16().chain([0]).collect();
    let mut out = 0u32;
    let mut len = 4u32;
    // SAFETY: NUL-terminated key/value names; `out` is a 4-byte buffer.
    let rc = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut out as *mut u32).cast(), &mut len) };
    (rc == 0).then_some(out)
}

/// Windows zone id → IANA (CLDR `windowsZones.xml`, territory 001, with the current canonical
/// names: Debian 13 moved the old aliases to `tzdata-legacy`).
const WINDOWS_ZONES: &[(&str, &str)] = &[
    ("Dateline Standard Time", "Etc/GMT+12"),
    ("UTC-11", "Etc/GMT+11"),
    ("Aleutian Standard Time", "America/Adak"),
    ("Hawaiian Standard Time", "Pacific/Honolulu"),
    ("Marquesas Standard Time", "Pacific/Marquesas"),
    ("Alaskan Standard Time", "America/Anchorage"),
    ("UTC-09", "Etc/GMT+9"),
    ("Pacific Standard Time (Mexico)", "America/Tijuana"),
    ("UTC-08", "Etc/GMT+8"),
    ("Pacific Standard Time", "America/Los_Angeles"),
    ("US Mountain Standard Time", "America/Phoenix"),
    ("Mountain Standard Time (Mexico)", "America/Mazatlan"),
    ("Mountain Standard Time", "America/Denver"),
    ("Yukon Standard Time", "America/Whitehorse"),
    ("Central America Standard Time", "America/Guatemala"),
    ("Central Standard Time", "America/Chicago"),
    ("Easter Island Standard Time", "Pacific/Easter"),
    ("Central Standard Time (Mexico)", "America/Mexico_City"),
    ("Canada Central Standard Time", "America/Regina"),
    ("SA Pacific Standard Time", "America/Bogota"),
    ("Eastern Standard Time (Mexico)", "America/Cancun"),
    ("Eastern Standard Time", "America/New_York"),
    ("Haiti Standard Time", "America/Port-au-Prince"),
    ("Cuba Standard Time", "America/Havana"),
    ("US Eastern Standard Time", "America/Indiana/Indianapolis"),
    ("Turks And Caicos Standard Time", "America/Grand_Turk"),
    ("Paraguay Standard Time", "America/Asuncion"),
    ("Atlantic Standard Time", "America/Halifax"),
    ("Venezuela Standard Time", "America/Caracas"),
    ("Central Brazilian Standard Time", "America/Cuiaba"),
    ("SA Western Standard Time", "America/La_Paz"),
    ("Pacific SA Standard Time", "America/Santiago"),
    ("Newfoundland Standard Time", "America/St_Johns"),
    ("Tocantins Standard Time", "America/Araguaina"),
    ("E. South America Standard Time", "America/Sao_Paulo"),
    ("SA Eastern Standard Time", "America/Cayenne"),
    ("Argentina Standard Time", "America/Argentina/Buenos_Aires"),
    ("Greenland Standard Time", "America/Nuuk"),
    ("Montevideo Standard Time", "America/Montevideo"),
    ("Magallanes Standard Time", "America/Punta_Arenas"),
    ("Saint Pierre Standard Time", "America/Miquelon"),
    ("Bahia Standard Time", "America/Bahia"),
    ("UTC-02", "Etc/GMT+2"),
    ("Azores Standard Time", "Atlantic/Azores"),
    ("Cape Verde Standard Time", "Atlantic/Cape_Verde"),
    ("UTC", "Etc/UTC"),
    ("GMT Standard Time", "Europe/London"),
    ("Greenwich Standard Time", "Atlantic/Reykjavik"),
    ("Sao Tome Standard Time", "Africa/Sao_Tome"),
    ("Morocco Standard Time", "Africa/Casablanca"),
    ("W. Europe Standard Time", "Europe/Berlin"),
    ("Central Europe Standard Time", "Europe/Budapest"),
    ("Romance Standard Time", "Europe/Paris"),
    ("Central European Standard Time", "Europe/Warsaw"),
    ("W. Central Africa Standard Time", "Africa/Lagos"),
    ("Jordan Standard Time", "Asia/Amman"),
    ("GTB Standard Time", "Europe/Bucharest"),
    ("Middle East Standard Time", "Asia/Beirut"),
    ("Egypt Standard Time", "Africa/Cairo"),
    ("E. Europe Standard Time", "Europe/Chisinau"),
    ("Syria Standard Time", "Asia/Damascus"),
    ("West Bank Standard Time", "Asia/Hebron"),
    ("South Africa Standard Time", "Africa/Johannesburg"),
    ("FLE Standard Time", "Europe/Kyiv"),
    ("Israel Standard Time", "Asia/Jerusalem"),
    ("South Sudan Standard Time", "Africa/Juba"),
    ("Kaliningrad Standard Time", "Europe/Kaliningrad"),
    ("Sudan Standard Time", "Africa/Khartoum"),
    ("Libya Standard Time", "Africa/Tripoli"),
    ("Namibia Standard Time", "Africa/Windhoek"),
    ("Arabic Standard Time", "Asia/Baghdad"),
    ("Turkey Standard Time", "Europe/Istanbul"),
    ("Arab Standard Time", "Asia/Riyadh"),
    ("Belarus Standard Time", "Europe/Minsk"),
    ("Russian Standard Time", "Europe/Moscow"),
    ("E. Africa Standard Time", "Africa/Nairobi"),
    ("Volgograd Standard Time", "Europe/Volgograd"),
    ("Iran Standard Time", "Asia/Tehran"),
    ("Arabian Standard Time", "Asia/Dubai"),
    ("Astrakhan Standard Time", "Europe/Astrakhan"),
    ("Azerbaijan Standard Time", "Asia/Baku"),
    ("Russia Time Zone 3", "Europe/Samara"),
    ("Mauritius Standard Time", "Indian/Mauritius"),
    ("Saratov Standard Time", "Europe/Saratov"),
    ("Georgian Standard Time", "Asia/Tbilisi"),
    ("Caucasus Standard Time", "Asia/Yerevan"),
    ("Afghanistan Standard Time", "Asia/Kabul"),
    ("West Asia Standard Time", "Asia/Tashkent"),
    ("Ekaterinburg Standard Time", "Asia/Yekaterinburg"),
    ("Pakistan Standard Time", "Asia/Karachi"),
    ("Qyzylorda Standard Time", "Asia/Qyzylorda"),
    ("India Standard Time", "Asia/Kolkata"),
    ("Sri Lanka Standard Time", "Asia/Colombo"),
    ("Nepal Standard Time", "Asia/Kathmandu"),
    ("Central Asia Standard Time", "Asia/Bishkek"),
    ("Bangladesh Standard Time", "Asia/Dhaka"),
    ("Omsk Standard Time", "Asia/Omsk"),
    ("Myanmar Standard Time", "Asia/Yangon"),
    ("SE Asia Standard Time", "Asia/Bangkok"),
    ("Altai Standard Time", "Asia/Barnaul"),
    ("W. Mongolia Standard Time", "Asia/Hovd"),
    ("North Asia Standard Time", "Asia/Krasnoyarsk"),
    ("N. Central Asia Standard Time", "Asia/Novosibirsk"),
    ("Tomsk Standard Time", "Asia/Tomsk"),
    ("China Standard Time", "Asia/Shanghai"),
    ("North Asia East Standard Time", "Asia/Irkutsk"),
    ("Singapore Standard Time", "Asia/Singapore"),
    ("W. Australia Standard Time", "Australia/Perth"),
    ("Taipei Standard Time", "Asia/Taipei"),
    ("Ulaanbaatar Standard Time", "Asia/Ulaanbaatar"),
    ("Aus Central W. Standard Time", "Australia/Eucla"),
    ("Transbaikal Standard Time", "Asia/Chita"),
    ("Tokyo Standard Time", "Asia/Tokyo"),
    ("North Korea Standard Time", "Asia/Pyongyang"),
    ("Korea Standard Time", "Asia/Seoul"),
    ("Yakutsk Standard Time", "Asia/Yakutsk"),
    ("Cen. Australia Standard Time", "Australia/Adelaide"),
    ("AUS Central Standard Time", "Australia/Darwin"),
    ("E. Australia Standard Time", "Australia/Brisbane"),
    ("AUS Eastern Standard Time", "Australia/Sydney"),
    ("West Pacific Standard Time", "Pacific/Port_Moresby"),
    ("Tasmania Standard Time", "Australia/Hobart"),
    ("Vladivostok Standard Time", "Asia/Vladivostok"),
    ("Lord Howe Standard Time", "Australia/Lord_Howe"),
    ("Bougainville Standard Time", "Pacific/Bougainville"),
    ("Russia Time Zone 10", "Asia/Srednekolymsk"),
    ("Magadan Standard Time", "Asia/Magadan"),
    ("Norfolk Standard Time", "Pacific/Norfolk"),
    ("Sakhalin Standard Time", "Asia/Sakhalin"),
    ("Central Pacific Standard Time", "Pacific/Guadalcanal"),
    ("Russia Time Zone 11", "Asia/Kamchatka"),
    ("New Zealand Standard Time", "Pacific/Auckland"),
    ("UTC+12", "Etc/GMT-12"),
    ("Fiji Standard Time", "Pacific/Fiji"),
    ("Chatham Islands Standard Time", "Pacific/Chatham"),
    ("UTC+13", "Etc/GMT-13"),
    ("Tonga Standard Time", "Pacific/Tongatapu"),
    ("Samoa Standard Time", "Pacific/Apia"),
    ("Line Islands Standard Time", "Pacific/Kiritimati"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn zone_names_are_checked() {
        for ok in ["Asia/Taipei", "Etc/GMT-8", "America/Argentina/Buenos_Aires", "UTC", "America/Port-au-Prince"] {
            assert!(valid_tz(ok), "{ok}");
        }
        for bad in ["", "../etc/passwd", "/Asia/Taipei", "Asia/Taipei,x", "Asia/Tai pei", "a'b", "$(id)"] {
            assert!(!valid_tz(bad), "{bad}");
        }
        assert!(WINDOWS_ZONES.iter().all(|(_, i)| valid_tz(i)));
        assert_eq!(resolve(""), None);
        assert_eq!(resolve("Europe/Berlin").as_deref(), Some("Europe/Berlin"));
    }

    #[test]
    fn the_unix_host_zone_comes_from_tz_then_localtime_then_etc_timezone() {
        assert_eq!(from_unix(Some(":Asia/Taipei"), None, None).as_deref(), Some("Asia/Taipei"));
        assert_eq!(from_unix(Some("CST-8"), Some(Path::new("/usr/share/zoneinfo/Asia/Tokyo")), None).as_deref(), Some("Asia/Tokyo"));
        assert_eq!(from_unix(None, Some(Path::new("/var/db/timezone/zoneinfo/Europe/Paris")), None).as_deref(), Some("Europe/Paris"));
        assert_eq!(from_unix(None, Some(Path::new("/etc/foo")), Some("America/Chicago\n")).as_deref(), Some("America/Chicago"));
        assert_eq!(from_unix(None, None, None), None);
    }

    #[test]
    fn windows_zones_map_to_iana_or_fall_back_to_the_offset() {
        assert_eq!(from_windows(Some("Taipei Standard Time"), Some(-480)).as_deref(), Some("Asia/Taipei"));
        assert_eq!(from_windows(Some("Some New Zone"), Some(-480)).as_deref(), Some("Etc/GMT-8"));
        assert_eq!(from_windows(None, Some(300)).as_deref(), Some("Etc/GMT+5"));
        assert_eq!(from_windows(None, Some(0)).as_deref(), Some("Etc/UTC"));
        assert_eq!(from_windows(None, Some(-330)), None); // India's +5:30 has no Etc/ zone
        assert_eq!(from_windows(None, None), None);
    }
}
