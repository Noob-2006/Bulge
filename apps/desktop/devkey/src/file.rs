//! The last-resort store: a PKCS#8 P-256 key in `<dir>/device-key.p8`, owner-only (0600 on
//! Unix; on Windows the app data folder is already per-user). Used only when the platform store
//! is unavailable, and for keys made by earlier versions.

use crate::{Kind, Store};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::path::Path;

pub const FILE: &str = "device-key.p8";

pub(crate) fn write_private(p: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, p).map_err(|e| format!("{}: {e}", p.display()))
}

pub struct FileStore {
    pair: EcdsaKeyPair,
}

impl FileStore {
    /// A key from PKCS#8 bytes (also used by the sealed Linux store).
    pub fn from_pkcs8(der: &[u8]) -> Result<FileStore, String> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new()).map(|pair| FileStore { pair }).map_err(|_| "bad device key".to_string())
    }

    /// A new PKCS#8 P-256 key.
    pub fn generate_pkcs8() -> Result<Vec<u8>, String> {
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new()).map(|d| d.as_ref().to_vec()).map_err(|_| "cannot create a device key".to_string())
    }

    /// The key in `dir`, created on first use.
    pub fn open(dir: &Path) -> Result<FileStore, String> {
        let p = dir.join(FILE);
        if let Ok(der) = std::fs::read(&p) {
            if let Ok(k) = FileStore::from_pkcs8(&der) {
                return Ok(k);
            }
        }
        let der = FileStore::generate_pkcs8()?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        write_private(&p, &der)?;
        FileStore::from_pkcs8(&der)
    }
}

impl Store for FileStore {
    fn kind(&self) -> Kind {
        Kind::File
    }
    fn public_point(&self) -> Result<Vec<u8>, String> {
        Ok(self.pair.public_key().as_ref().to_vec())
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        self.pair.sign(&SystemRandom::new(), msg).map(|s| s.as_ref().to_vec()).map_err(|_| "signing failed".to_string())
    }
}
