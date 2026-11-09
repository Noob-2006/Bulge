//! Windows: a persisted, non-exportable CNG key. First the **Microsoft Platform Crypto
//! Provider** (the key is generated and used inside the TPM), else the **Microsoft Software Key
//! Storage Provider** (DPAPI-protected per user, export policy 0 = not exportable). Signing is
//! `NCryptSignHash` over the SHA-256 digest, which already returns the `r ‖ s` form.

use crate::{Kind, Store};
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn provider(tpm: bool) -> PCWSTR {
    if tpm {
        MS_PLATFORM_CRYPTO_PROVIDER
    } else {
        MS_KEY_STORAGE_PROVIDER
    }
}

fn check(hr: i32, what: &str) -> Result<(), String> {
    if hr == 0 {
        Ok(())
    } else {
        Err(format!("{what}: 0x{:08x}", hr as u32))
    }
}

fn open_provider(tpm: bool) -> Result<NCRYPT_PROV_HANDLE, String> {
    let mut prov: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: out pointer to a local; the provider name is a static wide string.
    check(unsafe { NCryptOpenStorageProvider(&mut prov, provider(tpm), 0) }, "NCryptOpenStorageProvider")?;
    Ok(prov)
}

/// Is there a TPM-backed key storage provider?
pub fn platform_provider_available() -> bool {
    match open_provider(true) {
        Ok(p) => {
            // SAFETY: a handle we just opened.
            unsafe { NCryptFreeObject(p) };
            true
        }
        Err(_) => false,
    }
}

pub struct Cng {
    prov: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    tpm: bool,
}

// SAFETY: CNG key handles may be used from any thread (NCrypt is thread-safe per handle).
unsafe impl Send for Cng {}
unsafe impl Sync for Cng {}

impl Cng {
    /// Open the persisted key `name`, or create it when `create`.
    pub fn open(name: &str, tpm: bool, create: bool) -> Result<Cng, String> {
        let prov = open_provider(tpm)?;
        let wn = wide(name);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: valid provider handle, NUL-terminated name, out pointer to a local.
        let hr = unsafe { NCryptOpenKey(prov, &mut key, wn.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if hr == 0 {
            return Ok(Cng { prov, key, tpm });
        }
        if !create {
            // SAFETY: our provider handle.
            unsafe { NCryptFreeObject(prov) };
            return Err(format!("key `{name}` not found (0x{:08x})", hr as u32));
        }
        let made = (|| {
            // SAFETY: as above; the algorithm id is a static wide string.
            check(unsafe { NCryptCreatePersistedKey(prov, &mut key, BCRYPT_ECDSA_P256_ALGORITHM, wn.as_ptr(), 0, 0) }, "NCryptCreatePersistedKey")?;
            // Export policy 0: the private key can never be exported (the default, set explicitly).
            let policy: u32 = 0;
            // SAFETY: a 4-byte property value from a local.
            check(unsafe { NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, &policy as *const u32 as *const u8, 4, 0) }, "NCryptSetProperty(export policy)")?;
            // SAFETY: the key handle created above.
            check(unsafe { NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) }, "NCryptFinalizeKey")
        })();
        if let Err(e) = made {
            // SAFETY: free whatever was opened.
            unsafe {
                if key != 0 {
                    NCryptFreeObject(key);
                }
                NCryptFreeObject(prov);
            }
            return Err(e);
        }
        Ok(Cng { prov, key, tpm })
    }

    /// Delete the persisted key `name` (tests, forgetting the device).
    pub fn delete(name: &str, tpm: bool) -> Result<(), String> {
        let k = Cng::open(name, tpm, false)?;
        // SAFETY: NCryptDeleteKey frees the key handle itself.
        let hr = unsafe { NCryptDeleteKey(k.key, 0) };
        let prov = k.prov;
        std::mem::forget(k);
        // SAFETY: our provider handle.
        unsafe { NCryptFreeObject(prov) };
        check(hr, "NCryptDeleteKey")
    }
}

impl Drop for Cng {
    fn drop(&mut self) {
        // SAFETY: handles owned by this value.
        unsafe {
            NCryptFreeObject(self.key);
            NCryptFreeObject(self.prov);
        }
    }
}

impl Store for Cng {
    fn kind(&self) -> Kind {
        if self.tpm {
            Kind::Tpm
        } else {
            Kind::Cng
        }
    }
    fn public_point(&self) -> Result<Vec<u8>, String> {
        let mut len = 0u32;
        // SAFETY: size query (null output buffer).
        check(unsafe { NCryptExportKey(self.key, 0, BCRYPT_ECCPUBLIC_BLOB, std::ptr::null(), std::ptr::null_mut(), 0, &mut len, 0) }, "NCryptExportKey(size)")?;
        let mut blob = vec![0u8; len as usize];
        // SAFETY: buffer of the size CNG asked for.
        check(unsafe { NCryptExportKey(self.key, 0, BCRYPT_ECCPUBLIC_BLOB, std::ptr::null(), blob.as_mut_ptr(), len, &mut len, 0) }, "NCryptExportKey")?;
        // BCRYPT_ECCKEY_BLOB { ULONG dwMagic; ULONG cbKey; } then X and Y (cbKey bytes each).
        let cb = u32::from_le_bytes(blob.get(4..8).ok_or("short ECC blob")?.try_into().map_err(|_| "short ECC blob")?) as usize;
        let xy = blob.get(8..8 + 2 * cb).ok_or("short ECC blob")?;
        if cb != 32 {
            return Err("not a P-256 key".into());
        }
        let mut p = vec![4u8];
        p.extend_from_slice(xy);
        Ok(p)
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let digest = ring::digest::digest(&ring::digest::SHA256, msg);
        let mut sig = vec![0u8; 64];
        let mut got = 0u32;
        // SAFETY: 32-byte digest in, 64-byte buffer out.
        check(unsafe { NCryptSignHash(self.key, std::ptr::null(), digest.as_ref().as_ptr(), 32, sig.as_mut_ptr(), 64, &mut got, NCRYPT_SILENT_FLAG) }, "NCryptSignHash")?;
        sig.truncate(got as usize);
        Ok(sig)
    }
}
