//! `seagent secrets` through the real binary (A4): a throwaway `SEAGENT_HOME`, a key handed in through
//! `SEAGENT_VAULT_KEY`, so the run never touches the OS keyring, the TPM or polkit — an
//! unprivileged test must never open an authorisation dialog.
//!
//! What is asserted here is the operator-visible contract:
//! * `secrets set` writes ciphertext to `secrets.enc` (0600) and leaves no `secrets.toml`;
//! * `secrets backend` reports the backend and survives a missing/wrong key without panicking;
//! * `secrets migrate` folds an existing plaintext file in, is idempotent, and refuses to
//!   report success twice;
//! * `status --json` reports the same file and backend (the doctor/status wiring).
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// 32 bytes as hex; every test uses the same throwaway key.
const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Temp `SEAGENT_HOME`, removed when the test ends (even on panic).
struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(tag: &str) -> Home {
    let root = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let d = root.join(format!("seagent-vault-cli-{tag}-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(d.join("config")).unwrap();
    Home(d)
}

fn seagent(h: &Path, args: &[&str], stdin: Option<&str>, extra: &[(&str, &str)]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_seagent"));
    c.args(args).env("SEAGENT_HOME", h).env("SEAGENT_OFFLINE", "1").env_remove("SEAGENT_VAULT_PASSPHRASE").env_remove("SEAGENT_VAULT_PASSPHRASE_FILE");
    for (k, v) in extra {
        c.env(k, v);
    }
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().expect("run seagent");
    if let Some(s) = stdin {
        child.stdin.as_mut().unwrap().write_all(s.as_bytes()).unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("seagent output");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn env_key() -> Vec<(&'static str, &'static str)> {
    vec![("SEAGENT_VAULT_KEY", KEY), ("SEAGENT_VAULT_BACKEND", "env")]
}

#[cfg(unix)]
#[test]
fn secrets_are_encrypted_at_rest_and_reported_by_backend_and_status() {
    let h = home("store");
    let cfg = h.0.join("config");
    let (code, out, err) = seagent(&h.0, &["secrets", "set", "TOK"], Some("sup3r-s3cret-value\n"), &env_key());
    assert_eq!(code, 0, "{out}{err}");

    let enc = cfg.join("secrets.enc");
    assert!(enc.exists(), "the ciphertext file is what gets written");
    assert!(!cfg.join("secrets.toml").exists(), "no plaintext file is created");
    let body = std::fs::read(&enc).unwrap();
    assert!(!body.windows(6).any(|w| w == b"sup3r"), "no plaintext value on disk");
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&enc).unwrap().permissions().mode() & 0o777, 0o600);

    let (code, out, _) = seagent(&h.0, &["secrets", "list"], None, &env_key());
    assert_eq!((code, out.trim()), (0, "TOK"));

    let (code, out, err) = seagent(&h.0, &["secrets", "backend"], None, &env_key());
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("backend  env") && out.contains("secrets.enc"), "{out}");

    // The key is missing: `backend` still answers (it reads the header), and the failure of
    // `list` names the variable instead of looking like a corrupt file.
    let (code, out, _) = seagent(&h.0, &["secrets", "backend"], None, &[]);
    assert_eq!(code, 0);
    assert!(out.contains("env"), "{out}");
    let (code, _, err) = seagent(&h.0, &["secrets", "list"], None, &[]);
    assert_ne!(code, 0);
    assert!(err.contains("SEAGENT_VAULT_KEY"), "{err}");

    // Status reports the same file and backend without unlocking anything.
    let (code, out, err) = seagent(&h.0, &["status", "--json"], None, &[]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("\"secretsBackend\":\"env\"") && out.contains("secrets.enc"), "{out}");
}

#[cfg(unix)]
#[test]
fn migrate_folds_a_plaintext_file_in_and_is_idempotent() {
    let h = home("migrate");
    let cfg = h.0.join("config");
    let plain = cfg.join("secrets.toml");
    std::fs::write(&plain, "OLD = \"old-value\"\n").unwrap();
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code, out, err) = seagent(&h.0, &["secrets", "migrate"], None, &env_key());
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("1 secret"), "{out}");
    assert!(!plain.exists(), "the plaintext file is removed after the read-back check");
    assert!(cfg.join("secrets.enc").exists());

    let (code, out, _) = seagent(&h.0, &["secrets", "list"], None, &env_key());
    assert_eq!((code, out.trim()), (0, "OLD"));

    // Second run: an error that says why, not a silent success.
    let (code, _, err) = seagent(&h.0, &["secrets", "migrate"], None, &env_key());
    assert_ne!(code, 0);
    assert!(err.contains("already encrypted"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_passphrase_store_needs_the_passphrase_file_and_never_creates_one() {
    let h = home("pass");
    let cfg = h.0.join("config");
    let pass = h.0.join("pass");
    std::fs::write(&pass, "correct horse\n").unwrap();
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pass_s = pass.to_string_lossy().to_string();
    let args: Vec<(&str, &str)> = vec![("SEAGENT_VAULT_BACKEND", "passphrase"), ("SEAGENT_VAULT_PASSPHRASE_FILE", &pass_s), ("SEAGENT_VAULT_ITERATIONS", "100000")];

    let (code, out, err) = seagent(&h.0, &["secrets", "set", "TOK"], Some("value-123456\n"), &args);
    assert_eq!(code, 0, "{out}{err}");
    let header = std::fs::read_to_string(cfg.join("secrets.enc")).unwrap();
    assert!(header.contains("backend = \"passphrase\"") && header.contains("pbkdf2-hmac-sha256"), "{header}");
    assert!(!header.contains("value-123456") && !header.contains("correct horse"));

    // Wrong passphrase is refused with one message; the passphrase itself is never written.
    let wrong = h.0.join("wrong");
    std::fs::write(&wrong, "nope\n").unwrap();
    std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wrong_s = wrong.to_string_lossy().to_string();
    let (code, _, err) = seagent(&h.0, &["secrets", "list"], None, &[("SEAGENT_VAULT_BACKEND", "passphrase"), ("SEAGENT_VAULT_PASSPHRASE_FILE", &wrong_s)]);
    assert_ne!(code, 0);
    assert!(err.contains("wrong key"), "{err}");
}
