//! macOS / iOS: a P-256 key in the Keychain, generated inside the **Secure Enclave** when the
//! device has one (the private key never exists outside it), otherwise a software Keychain key.
//! Found again by its label. Signatures come back as X9.62 DER and are converted to `r ‖ s`.

use crate::{der_to_p1363, Kind, Store};
use security_framework::item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

pub struct Keychain {
    key: SecKey,
    enclave: bool,
}

// SAFETY: SecKey is a CoreFoundation object; Security.framework keys are thread-safe to use.
unsafe impl Send for Keychain {}
unsafe impl Sync for Keychain {}

fn find(label: &str) -> Option<SecKey> {
    let found = ItemSearchOptions::new().class(ItemClass::key()).key_class(KeyClass::private()).label(label).load_refs(true).search().ok()?;
    found.into_iter().find_map(|r| match r {
        SearchResult::Ref(Reference::Key(k)) => Some(k),
        _ => None,
    })
}

impl Keychain {
    pub fn open(label: &str, enclave: bool, create: bool) -> Result<Keychain, String> {
        if let Some(key) = find(label) {
            return Ok(Keychain { key, enclave });
        }
        if !create {
            return Err(format!("Keychain key `{label}` not found"));
        }
        let mut o = GenerateKeyOptions::default();
        o.set_key_type(KeyType::ec_sec_prime_random()).set_size_in_bits(256).set_label(label);
        if enclave {
            o.set_token(Token::SecureEnclave).set_location(Location::DataProtectionKeychain);
        } else {
            #[cfg(target_os = "macos")]
            o.set_location(Location::DefaultFileKeychain);
            #[cfg(target_os = "ios")]
            o.set_location(Location::DataProtectionKeychain);
        }
        let key = SecKey::new(&o).map_err(|e| format!("SecKeyCreateRandomKey: {e}"))?;
        Ok(Keychain { key, enclave })
    }

    pub fn delete(label: &str) -> Result<(), String> {
        match find(label) {
            Some(k) => k.delete().map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }
}

impl Store for Keychain {
    fn kind(&self) -> Kind {
        if self.enclave {
            Kind::SecureEnclave
        } else {
            Kind::Keychain
        }
    }
    fn public_point(&self) -> Result<Vec<u8>, String> {
        let p = self.key.public_key().ok_or("no public key")?;
        Ok(p.external_representation().ok_or("public key not exportable")?.bytes().to_vec())
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let der = self.key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg).map_err(|e| e.to_string())?;
        der_to_p1363(&der)
    }
}
