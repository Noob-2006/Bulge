//! This install's device key (docs/SECURITY.md §8): `seagent-devkey` (apps/desktop/devkey)
//! keeps it in the platform key store — TPM / CNG on Windows, Secure Enclave / Keychain on macOS
//! and iOS, systemd-creds TPM on Linux (root) — with the Android Keystore handed in from here
//! through the mobile plugin. A file is only the fallback. Hosts paired by an older version get
//! the key on the next `host_open` (the host binds it once: automatic migration).

pub use seagent_devkey::DeviceKey;
use std::path::Path;
use tauri::{AppHandle, Runtime};

/// The Android Keystore through `tauri-plugin-seagent-mobile` (DeviceKeystore.kt).
#[cfg(target_os = "android")]
struct AndroidKeystore<R: Runtime>(AppHandle<R>);

#[cfg(target_os = "android")]
const ALIAS: &str = "seagent-device";

#[cfg(target_os = "android")]
impl<R: Runtime> seagent_devkey::Store for AndroidKeystore<R> {
    fn kind(&self) -> seagent_devkey::Kind {
        seagent_devkey::Kind::AndroidKeystore
    }
    fn public_point(&self) -> Result<Vec<u8>, String> {
        use base64::Engine;
        use tauri_plugin_seagent_mobile::SeagentMobileExt;
        let v = self.0.seagent_mobile().device_key_public(ALIAS)?;
        let spki = base64::engine::general_purpose::STANDARD.decode(v["spki"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
        seagent_devkey::spki_to_point(&spki)
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        use base64::Engine;
        use tauri_plugin_seagent_mobile::SeagentMobileExt;
        let b64 = base64::engine::general_purpose::STANDARD;
        let der = b64.decode(self.0.seagent_mobile().device_key_sign(ALIAS, &b64.encode(msg))?).map_err(|e| e.to_string())?;
        seagent_devkey::der_to_p1363(&der)
    }
}

/// The key, opened (or created once) for this install.
pub fn load<R: Runtime>(app: &AppHandle<R>, dir: &Path) -> Result<DeviceKey, String> {
    #[cfg(target_os = "android")]
    let external: Option<Box<dyn seagent_devkey::Store>> = Some(Box::new(AndroidKeystore(app.clone())));
    #[cfg(not(target_os = "android"))]
    let external: Option<Box<dyn seagent_devkey::Store>> = {
        let _ = app;
        None
    };
    seagent_devkey::open(dir, external)
}

/// Whether a failure is worth retrying.
#[derive(Debug)]
pub enum Transient {
    /// Network down, host restarting, a refresh signed just before a restart.
    Again(String),
    /// The host said no (revoked, wrong key): retrying will not help.
    Final(String),
}

/// Retry `f` on transient failures: 3 tries, 0.5 s and 1.5 s apart.
pub async fn with_retry<T, F, Fut>(mut f: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, Transient>>,
{
    let mut last = String::new();
    for (i, wait) in [500u64, 1500, 0].iter().enumerate() {
        match f().await {
            Ok(v) => return Ok(v),
            Err(Transient::Final(e)) => return Err(e),
            Err(Transient::Again(e)) => {
                last = e;
                if i < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(*wait)).await;
                }
            }
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_failures_are_retried_and_final_ones_are_not() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let mut n = 0;
        let r: Result<u32, String> = rt.block_on(with_retry(|| {
            n += 1;
            let k = n;
            async move {
                if k < 3 {
                    Err(Transient::Again("host restarting".into()))
                } else {
                    Ok(k)
                }
            }
        }));
        assert_eq!(r.unwrap(), 3, "two transient failures, then success");
        let mut m = 0;
        let r: Result<u32, String> = rt.block_on(with_retry(|| {
            m += 1;
            async { Err(Transient::Final("revoked".into())) }
        }));
        assert_eq!((r.unwrap_err().as_str(), m), ("revoked", 1), "a refusal is not retried");
    }
}
