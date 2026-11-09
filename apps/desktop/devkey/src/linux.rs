//! Linux: the PKCS#8 key sealed to the TPM with `systemd-creds encrypt --with-key=tpm2` in
//! `<dir>/device-key.tpm` — the same mechanism the agent's vault uses
//! (`crates/seagent-kernel/src/secretstore.rs`, backend `tpm`). Like there, it is chosen
//! automatically only for root: for any other user every `systemd-creds decrypt` goes through
//! polkit and would ask for a password at each start. `SEAGENT_DEVICE_KEY_STORE=tpm` forces it.
//! The key exists in this process's memory while the app runs (as the vault key does).

use crate::file::{write_private, FileStore};
use crate::{Kind, Store};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const SEALED: &str = "device-key.tpm";
const NAME: &str = "seagent-device-key";

/// `systemd-creds` (`SEAGENT_CREDS_TOOL` overrides it: tests use a stand-in script).
pub fn tool() -> PathBuf {
    std::env::var_os("SEAGENT_CREDS_TOOL").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("systemd-creds"))
}

fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
}

fn has_tpm(tool: &Path) -> bool {
    Path::new("/dev/tpmrm0").exists() && Command::new(tool).arg("has-tpm2").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// The automatic choice: a TPM is there and no polkit prompt would follow.
pub fn available() -> bool {
    is_root() && has_tpm(&tool())
}

fn run(tool: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut c = Command::new(tool).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{}: {e}", tool.display()))?;
    c.stdin.take().ok_or("no stdin")?.write_all(input).map_err(|e| e.to_string())?;
    let out = c.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("{} {}: {}", tool.display(), args.first().unwrap_or(&""), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(out.stdout)
}

pub struct Sealed {
    inner: FileStore,
}

impl Sealed {
    pub fn open(dir: &Path, create: bool, tool: &Path) -> Result<Sealed, String> {
        let p = dir.join(SEALED);
        if let Ok(blob) = std::fs::read(&p) {
            let der = run(tool, &["decrypt", &format!("--name={NAME}"), "-", "-"], &blob)?;
            return Ok(Sealed { inner: FileStore::from_pkcs8(&der)? });
        }
        if !create {
            return Err(format!("{} is missing", p.display()));
        }
        let der = FileStore::generate_pkcs8()?;
        let blob = run(tool, &["encrypt", "--with-key=tpm2", &format!("--name={NAME}"), "-", "-"], &der)?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        write_private(&p, &blob)?;
        Ok(Sealed { inner: FileStore::from_pkcs8(&der)? })
    }
}

impl Store for Sealed {
    fn kind(&self) -> Kind {
        Kind::Tpm
    }
    fn public_point(&self) -> Result<Vec<u8>, String> {
        self.inner.public_point()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        self.inner.sign(msg)
    }
}
