use super::*;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("seagent-devkey-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn verifies(k: &DeviceKey) {
    let pk = URL_SAFE_NO_PAD.decode(k.public_b64().unwrap()).unwrap();
    assert_eq!((pk.len(), pk[0]), (65, 4));
    let msg = refresh_message("0123456789abcdef", "dev1", 1_700_000_000_000, "nonce-0000000000001");
    let sig = URL_SAFE_NO_PAD.decode(k.sign_b64(msg.as_bytes()).unwrap()).unwrap();
    assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pk).verify(msg.as_bytes(), &sig).is_ok(), "{:?} signs what the host verifies", k.kind());
    assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pk).verify(b"other", &sig).is_err());
}

#[test]
fn the_best_available_store_comes_first_and_the_file_is_always_last() {
    let all = Probe { windows_tpm: true, secure_enclave: true, keychain: true, android_keystore: true, linux_tpm: true };
    let none = Probe::default();
    assert_eq!(candidates(Os::Windows, &all), [Kind::Tpm, Kind::Cng, Kind::File]);
    assert_eq!(candidates(Os::Windows, &none), [Kind::Cng, Kind::File], "no TPM: the software KSP");
    assert_eq!(candidates(Os::Macos, &all), [Kind::SecureEnclave, Kind::Keychain, Kind::File]);
    assert_eq!(candidates(Os::Ios, &Probe { keychain: true, ..none }), [Kind::Keychain, Kind::File], "no Secure Enclave");
    assert_eq!(candidates(Os::Android, &all), [Kind::AndroidKeystore, Kind::File]);
    assert_eq!(candidates(Os::Android, &none), [Kind::File], "no bridge: file");
    assert_eq!(candidates(Os::Linux, &all), [Kind::Tpm, Kind::File]);
    assert_eq!(candidates(Os::Linux, &none), [Kind::File], "no TPM or not root: file");
    assert_eq!(candidates(Os::Other, &all), [Kind::File]);
    assert_eq!(forced(candidates(Os::Windows, &all), Some("cng")).unwrap(), [Kind::Cng]);
    assert_eq!(forced(candidates(Os::Windows, &all), None).unwrap().len(), 3);
    assert!(forced(vec![], Some("vault")).is_err());
    for k in [Kind::Tpm, Kind::Cng, Kind::SecureEnclave, Kind::Keychain, Kind::AndroidKeystore, Kind::File] {
        assert_eq!(Kind::parse(k.as_str()), Some(k));
    }
}

#[test]
fn the_record_pins_the_store_and_an_old_file_key_is_kept() {
    let d = tmp("record");
    // A key from the previous version (device-key.p8) stays: the host may have bound it.
    let old = FileStore::open(&d).unwrap();
    let k = open(&d, None).unwrap();
    assert_eq!(k.kind(), Kind::File);
    assert_eq!(k.public_b64().unwrap(), URL_SAFE_NO_PAD.encode(old.public_point().unwrap()));
    assert_eq!(Record::load(&d).unwrap().store, Kind::File);
    assert_eq!(describe(&d).as_deref(), Some("file"));
    // A recorded store that cannot be opened is an error, never a silent new key.
    Record { store: Kind::AndroidKeystore, name: "x".into() }.save(&d).unwrap();
    assert!(open(&d, None).unwrap_err().contains("pair it again"));
    destroy(&d).unwrap();
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn a_store_handed_in_by_the_app_is_used_and_recorded() {
    // What the Android Keystore bridge looks like from here (a file store stands in for it).
    struct Bridge(FileStore);
    impl Store for Bridge {
        fn kind(&self) -> Kind {
            Kind::AndroidKeystore
        }
        fn public_point(&self) -> Result<Vec<u8>, String> {
            self.0.public_point()
        }
        fn sign(&self, m: &[u8]) -> Result<Vec<u8>, String> {
            self.0.sign(m)
        }
    }
    if Os::current() != Os::Android {
        return; // the selection only offers it on Android; the plumbing is the same
    }
    let d = tmp("bridge");
    let k = open(&d, Some(Box::new(Bridge(FileStore::from_pkcs8(&FileStore::generate_pkcs8().unwrap()).unwrap())))).unwrap();
    assert_eq!(k.kind(), Kind::AndroidKeystore);
    verifies(&k);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn der_signatures_and_spki_keys_convert_to_the_wire_form() {
    // r has a leading 0x00 (high bit set), s is short (leading zero bytes dropped).
    let mut der = vec![0x30, 0x43, 0x02, 0x21, 0x00];
    der.extend([0x80; 32]);
    der.extend([0x02, 0x1e]);
    der.extend([0x11; 30]);
    let fixed = der_to_p1363(&der).unwrap();
    assert_eq!(fixed.len(), 64);
    assert_eq!(&fixed[..32], &[0x80; 32]);
    assert_eq!(&fixed[32..34], &[0, 0]);
    assert_eq!(&fixed[34..], &[0x11; 30]);
    assert!(der_to_p1363(&[0x31, 0]).is_err() && der_to_p1363(&[]).is_err());
    let mut spki = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04];
    spki.extend([7u8; 64]);
    let p = spki_to_point(&spki).unwrap();
    assert_eq!((p.len(), p[0]), (65, 4));
    assert!(spki_to_point(&spki[1..]).is_err());
}

#[test]
fn the_refresh_body_carries_the_store_and_the_host_format() {
    let d = tmp("body");
    let k = DeviceKey::from_store(Box::new(FileStore::open(&d).unwrap()));
    let b = k.refresh_body("0123456789abcdef", "dev1", 42).unwrap();
    for part in ["\"deviceId\":\"dev1\"", "\"ts\":42", "\"keyStore\":\"file\"", "\"publicKey\":\""] {
        assert!(b.contains(part), "{b}");
    }
    assert_eq!(json_field(&b, "keyStore").as_deref(), Some("file"));
    verifies(&k);
    let _ = std::fs::remove_dir_all(d);
}

/// The real platform store of the machine running the tests: on Windows a TPM or software-KSP
/// CNG key, on a Mac the Keychain / Secure Enclave, on Linux the sealed (or file) key. Created,
/// reopened from its record, used, deleted.
#[test]
fn this_platforms_store_creates_reopens_signs_and_deletes() {
    let d = tmp("platform");
    let k = open(&d, None).unwrap();
    let kind = k.kind();
    eprintln!("device key store on this machine: {}", kind.as_str());
    #[cfg(windows)]
    assert!(matches!(kind, Kind::Tpm | Kind::Cng), "Windows never needs the file: {kind:?}");
    verifies(&k);
    let pk = k.public_b64().unwrap();
    drop(k);
    let again = open(&d, None).unwrap();
    assert_eq!((again.kind(), again.public_b64().unwrap()), (kind, pk), "the same key from its record");
    destroy(&d).unwrap();
    let _ = std::fs::remove_dir_all(d);
}

/// Windows: both CNG providers, explicitly (the TPM one only where a TPM is present).
#[cfg(windows)]
#[test]
fn both_cng_providers_keep_a_non_exportable_key() {
    for tpm in [false, true] {
        if tpm && !win::platform_provider_available() {
            eprintln!("no Platform Crypto Provider (TPM) on this machine");
            continue;
        }
        let name = format!("seagent-devkey-test-{}-{tpm}", std::process::id());
        let c = win::Cng::open(&name, tpm, true).unwrap();
        let k = DeviceKey::from_store(Box::new(c));
        assert_eq!(k.kind(), if tpm { Kind::Tpm } else { Kind::Cng });
        verifies(&k);
        drop(k);
        assert!(win::Cng::open(&name, tpm, false).is_ok(), "persisted");
        win::Cng::delete(&name, tpm).unwrap();
        assert!(win::Cng::open(&name, tpm, false).is_err(), "deleted");
    }
}

/// Linux: the sealed store through a stand-in `systemd-creds` (no TPM, no polkit in tests).
#[cfg(all(target_os = "linux", not(target_os = "android")))]
#[test]
fn the_linux_tpm_store_seals_through_systemd_creds() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp("sealed");
    std::fs::create_dir_all(&d).unwrap();
    // "Seals" by prefixing a marker, "unseals" by stripping it.
    let tool = d.join("fake-creds");
    std::fs::write(&tool, "#!/bin/sh\ncase \"$1\" in\n encrypt) printf SEALED; cat ;;\n decrypt) tail -c +7 ;;\n has-tpm2) exit 0 ;;\nesac\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let s = linux::Sealed::open(&d, true, &tool).unwrap();
    let k = DeviceKey::from_store(Box::new(s));
    assert_eq!(k.kind(), Kind::Tpm);
    verifies(&k);
    let blob = std::fs::read(d.join(linux::SEALED)).unwrap();
    assert!(blob.starts_with(b"SEALED"), "only the sealed blob is on disk");
    assert!(!d.join(file::FILE).exists());
    let again = DeviceKey::from_store(Box::new(linux::Sealed::open(&d, false, &tool).unwrap()));
    assert_eq!(again.public_b64().unwrap(), k.public_b64().unwrap());
    let _ = std::fs::remove_dir_all(d);
}
