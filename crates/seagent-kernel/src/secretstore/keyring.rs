//! The `keyring` backend's OS key holder: where the store's random data key lives.
//!
//! * **Linux and other Unixes** — Secret Service through the `secret-tool` CLI (libsecret),
//!   exactly as before. The same CLI protocol is used on any OS when a stand-in tool is
//!   configured (`Options::keyring_tool`, the tests).
//! * **macOS** — the login Keychain through `/usr/bin/security` (no new crate). The key is
//!   written with `security -i` reading its command from stdin, so it never appears in a
//!   process argument list; it is read back with `find-generic-password -w`.
//! * **Windows** — DPAPI (`CryptProtectData`, user scope, no UI) seals the key into
//!   `<store>.dpapi`, created with an owner-only DACL. Only the same Windows account on the
//!   same machine can unseal it; a copied file is useless elsewhere. This is the Windows
//!   counterpart of "held by the login keyring".
//! * **Android / iOS** — there is no CLI keyring an app process can call; the host app owns
//!   Android Keystore / the iOS Keychain. The backend reports itself unavailable with that
//!   explanation, so the store falls back to `passphrase` / `env` (or, explicitly, plaintext in
//!   the app sandbox) instead of pretending.

use std::path::{Path, PathBuf};

/// One way to hold the key.
pub enum Holder {
    /// `secret-tool` (or a stand-in speaking its protocol).
    SecretTool(PathBuf),
    /// `/usr/bin/security`.
    #[cfg(target_os = "macos")]
    Keychain(PathBuf),
    /// The DPAPI blob next to the store.
    #[cfg(windows)]
    Dpapi(PathBuf),
}

/// Why no holder is available on this OS (for the error the backend returns).
pub fn missing() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "/usr/bin/security (the macOS Keychain CLI) was not found"
    }
    #[cfg(windows)]
    {
        "DPAPI is not available"
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        "the keyring backend is not available on mobile: the host app must hold the key in Android Keystore / the iOS Keychain and pass it as SEAGENT_VAULT_KEY (env backend)"
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "android", target_os = "ios")))]
    {
        "secret-tool is not installed (apt install libsecret-tools)"
    }
}

/// The holder for the store at `store` (`secrets.enc`). `stand_in` is a configured
/// `secret-tool` replacement (already checked to exist); `on_path` finds the real one.
pub fn holder(stand_in: Option<PathBuf>, on_path: impl Fn(&str) -> Option<PathBuf>, store: &Path) -> Option<Holder> {
    if let Some(p) = stand_in {
        return Some(Holder::SecretTool(p));
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (&on_path, store);
        let p = PathBuf::from("/usr/bin/security");
        p.is_file().then_some(Holder::Keychain(p))
    }
    #[cfg(windows)]
    {
        let _ = &on_path;
        Some(Holder::Dpapi(store.with_extension("dpapi")))
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = (&on_path, store);
        None
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "android", target_os = "ios")))]
    {
        let _ = store;
        on_path("secret-tool").map(Holder::SecretTool)
    }
}

impl Holder {
    /// Needs a desktop session to work at all? (Secret Service lives on the session D-Bus.)
    pub fn needs_session_bus(&self) -> bool {
        matches!(self, Holder::SecretTool(_))
    }

    /// The key text stored for (`service`, `account`); `Err` with the tool's message when
    /// there is none (or the holder is locked).
    pub fn lookup(&self, service: &str, account: &str) -> Result<String, String> {
        match self {
            Holder::SecretTool(t) => {
                let out = super::run(t, &["lookup", "service", service, "account", account], None)?;
                String::from_utf8(out).map_err(|_| "the keyring returned non-UTF-8 data".to_string())
            }
            #[cfg(target_os = "macos")]
            Holder::Keychain(t) => {
                let out = super::run(t, &["find-generic-password", "-s", service, "-a", account, "-w"], None)?;
                String::from_utf8(out).map_err(|_| "the Keychain returned non-UTF-8 data".to_string())
            }
            #[cfg(windows)]
            Holder::Dpapi(p) => {
                if service != super::KEYRING_SERVICE {
                    return Err("no DPAPI entry under the pre-rename name".into());
                }
                let _ = account;
                let blob = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
                let plain = dpapi::unprotect(&blob)?;
                String::from_utf8(plain).map_err(|_| "DPAPI returned non-UTF-8 data".to_string())
            }
        }
    }

    /// Store `secret` for `account` under the current service name.
    pub fn store(&self, account: &str, secret: &str) -> Result<(), String> {
        match self {
            Holder::SecretTool(t) => super::store_in_keyring(t, account, secret),
            #[cfg(target_os = "macos")]
            Holder::Keychain(t) => {
                // `security -i` reads commands from stdin: the key stays out of argv.
                let q = |s: &str| -> Result<String, String> {
                    if s.contains(['"', '\\', '\n', '\r']) {
                        return Err(format!("cannot pass {s:?} to the Keychain CLI"));
                    }
                    Ok(format!("\"{s}\""))
                };
                let line = format!("add-generic-password -U -l {} -s {} -a {} -w {}\n", q("seagent secret store")?, q(super::KEYRING_SERVICE)?, q(account)?, q(secret)?);
                let out = super::run_with_input(t, &["-i"], line.as_bytes()).map_err(|e| format!("security add-generic-password failed: {e}"))?;
                let said = String::from_utf8_lossy(&out);
                if said.to_ascii_lowercase().contains("error") {
                    return Err(format!("security add-generic-password failed: {}", said.trim()));
                }
                Ok(())
            }
            #[cfg(windows)]
            Holder::Dpapi(p) => {
                let _ = account;
                let blob = dpapi::protect(secret.as_bytes())?;
                if let Some(d) = p.parent() {
                    std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
                }
                seagent_core::platform::fs_private::write_private(p, &blob).map_err(|e| format!("{}: {e}", p.display()))
            }
        }
    }
}

#[cfg(windows)]
mod dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};

    /// Domain separation: a DPAPI blob made by another program for the same user does not
    /// unseal here, nor ours there.
    const ENTROPY: &[u8] = b"seagent-secret-store-v1";

    fn call(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: the input blobs point at live slices that DPAPI only reads; `out` is filled by
        // the call with a LocalAlloc'd buffer that is copied and freed below.
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            }
        };
        if ok == 0 {
            return Err(format!("DPAPI {} failed: {}", if protect { "CryptProtectData" } else { "CryptUnprotectData" }, std::io::Error::last_os_error()));
        }
        // SAFETY: on success `out` describes `cbData` readable bytes owned by us.
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe { LocalFree(out.pbData.cast()) };
        Ok(v)
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        call(data, true)
    }

    pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
        call(blob, false)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn round_trip_and_tamper() {
            let b = super::protect(b"k3y").unwrap();
            assert_eq!(super::unprotect(&b).unwrap(), b"k3y");
            let mut bad = b.clone();
            let n = bad.len() - 1;
            bad[n] ^= 1;
            assert!(super::unprotect(&bad).is_err());
        }
    }
}
