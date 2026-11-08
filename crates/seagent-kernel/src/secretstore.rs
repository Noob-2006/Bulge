//! Secret store: the on-disk half of A4. Secrets used to live in a 0600 plaintext
//! `secrets.toml`; anyone with a read of the file (a backup, a profile export, a
//! mis-permissioned copy, a stolen laptop) had every key in the clear.
//!
//! What this module guarantees, and where the guarantee stops:
//!
//! * **At rest** every secret lives in `secrets.enc`, a ChaCha20-Poly1305 ciphertext
//!   (see [`seagent_security::secretbox`]). The file's header (backend, KDF, iterations, salt)
//!   is authenticated as AEAD associated data, so it cannot be downgraded without the tag
//!   failing.
//! * **The key never sits next to the ciphertext.** Four sources, in the order they are
//!   tried for a *new* store:
//!   1. `keyring` — Secret Service, through the `secret-tool` CLI (libsecret). The key is
//!      held by the login keyring and unlocked with the user's session.
//!   2. `tpm` — a random data key sealed with `systemd-creds --with-key=tpm2` into
//!      `secrets.key`; unsealing needs the TPM (and thus the machine), not a copy of the file.
//!   3. `passphrase` — PBKDF2-HMAC-SHA256 of `SEAGENT_VAULT_PASSPHRASE` /
//!      `SEAGENT_VAULT_PASSPHRASE_FILE` (600k iterations), no key file at all.
//!   4. `env` — `SEAGENT_VAULT_KEY` (32 bytes hex/base64) for a daemon whose secret is provided by
//!      systemd `LoadCredential` or a secrets manager at start.
//!
//!   An existing store always opens with the backend recorded in its own header.
//! * **Fallback is explicit, never silent.** If no source is available the store stays
//!   plaintext (`secrets.toml`, 0600 — what seagent did before) and says so through
//!   [`Store::notes`], `seagent secrets backend` and `seagent doctor`. `SEAGENT_VAULT_REQUIRE_ENCRYPTION=1`
//!   turns the fallback into a hard error for operators who want that.
//! * **Migration is one-way and verified.** A plaintext file is read, written encrypted, read
//!   back and compared, and only then overwritten with zeros and removed.
//! * **What this does not do**: it does not protect against a root-level attacker on a running
//!   machine (the daemon holds decrypted secrets in memory by necessity), and it does not
//!   replace keeping secrets out of the VM — the broker injects them at the boundary. See
//!   `docs/SECURITY.md`.

//!
//! Per OS (docs/cross-platform.md): `keyring` is Secret Service on Linux, the login Keychain on
//! macOS and DPAPI on Windows (see `keyring.rs`); `tpm` is Linux-only (systemd-creds); on
//! Android / iOS the host app holds the key (Keystore / Keychain) and hands it over as
//! `SEAGENT_VAULT_KEY`, so `env` or `passphrase` are the backends there.

mod keyring;

use seagent_security::secretbox;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Env var holding a raw 32-byte key (hex or base64).
pub const ENV_KEY: &str = "SEAGENT_VAULT_KEY";
/// Env var holding the passphrase itself (avoid: visible in `/proc/<pid>/environ`).
pub const ENV_PASSPHRASE: &str = "SEAGENT_VAULT_PASSPHRASE";
/// Env var naming a 0600 file that holds the passphrase (preferred over the var).
pub const ENV_PASSPHRASE_FILE: &str = "SEAGENT_VAULT_PASSPHRASE_FILE";
/// Force a backend: `keyring`, `tpm`, `passphrase`, `env` or `plaintext`.
pub const ENV_BACKEND: &str = "SEAGENT_VAULT_BACKEND";
/// Refuse the plaintext fallback.
pub const ENV_REQUIRE: &str = "SEAGENT_VAULT_REQUIRE_ENCRYPTION";
/// Override the iteration count (tests only; the value is floored by `secretbox`).
pub const ENV_ITERATIONS: &str = "SEAGENT_VAULT_ITERATIONS";

/// File that holds the ciphertext (the plaintext file keeps its old name).
const STORE_SUFFIX: &str = "enc";
/// Sealed data key for the `tpm` backend, next to the store.
const KEY_SUFFIX: &str = "key";
/// `secret-tool` attributes: one account per store path, one service name for seagent.
const KEYRING_SERVICE: &str = "seagent";
const CREDS_NAME: &str = "seagent-vault-key";
/// Names this store used before the product was renamed (ark → SE Agent): a key kept there is
/// still found, and copied to the new name on first use.
const LEGACY_KEYRING_SERVICE: &str = "ark";
const LEGACY_CREDS_NAME: &str = "ark-vault-key";

/// The store path under the old directory name (`…/ark/secrets.toml` for `…/seagent/…`), for
/// a keyring entry made before the rename moved the directory.
fn legacy_store_path(store: &Path) -> PathBuf {
    store.iter().map(|c| if c == "seagent" { std::ffi::OsStr::new("ark") } else { c }).collect()
}

/// Where the store's key comes from. Recorded in the file header and re-used on open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Secret Service via `secret-tool`.
    Keyring,
    /// A data key sealed to the TPM (`systemd-creds`).
    Tpm,
    /// PBKDF2 over a passphrase that only exists in memory.
    Passphrase,
    /// A key handed to the daemon through the environment.
    Env,
    /// No encryption: the pre-A4 plaintext file. Only when nothing else is available.
    Plaintext,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Keyring => "keyring",
            Backend::Tpm => "tpm",
            Backend::Passphrase => "passphrase",
            Backend::Env => "env",
            Backend::Plaintext => "plaintext",
        }
    }
    pub fn parse(s: &str) -> Option<Backend> {
        match s.trim().to_ascii_lowercase().as_str() {
            "keyring" | "secret-service" | "secretservice" => Some(Backend::Keyring),
            "tpm" | "tpm2" => Some(Backend::Tpm),
            "passphrase" | "password" => Some(Backend::Passphrase),
            "env" | "key" => Some(Backend::Env),
            "plaintext" | "none" => Some(Backend::Plaintext),
            _ => None,
        }
    }
    /// Is the file on disk ciphertext? (`Plaintext` is the compatibility mode.)
    pub fn encrypted(self) -> bool {
        self != Backend::Plaintext
    }
    /// Human sentence for `seagent secrets backend` / `seagent doctor`.
    pub fn explain(self) -> &'static str {
        match self {
            #[cfg(target_os = "macos")]
            Backend::Keyring => "encrypted, key in the OS keyring (the macOS login Keychain)",
            #[cfg(windows)]
            Backend::Keyring => "encrypted, key sealed with Windows DPAPI for this account (secrets.dpapi)",
            #[cfg(not(any(target_os = "macos", windows)))]
            Backend::Keyring => "encrypted, key in the OS keyring (Secret Service via secret-tool)",
            Backend::Tpm => "encrypted, data key sealed to the TPM (systemd-creds --with-key=tpm2)",
            Backend::Passphrase => "encrypted, key derived from the passphrase (PBKDF2-HMAC-SHA256)",
            Backend::Env => "encrypted, key from SEAGENT_VAULT_KEY (hex or base64, 32 bytes)",
            Backend::Plaintext => "PLAINTEXT secrets.toml (0600) — no key source was available",
        }
    }
}

/// Everything the store needs from its environment, injected so tests never mutate process
/// env and so a daemon can be explicit about where its key comes from.
#[derive(Clone, Default)]
pub struct Options {
    /// Force a backend instead of detecting one.
    pub backend: Option<Backend>,
    /// Raw key for [`Backend::Env`].
    pub key: Option<[u8; 32]>,
    /// Passphrase for [`Backend::Passphrase`].
    pub passphrase: Option<String>,
    /// PBKDF2 iterations for a new passphrase store (`0` = default).
    pub iterations: u32,
    /// Refuse the plaintext fallback.
    pub require_encryption: bool,
    /// `secret-tool` override (tests use a stand-in script).
    pub keyring_tool: Option<PathBuf>,
    /// `systemd-creds` override.
    pub creds_tool: Option<PathBuf>,
}

impl Options {
    /// Read `SEAGENT_VAULT_*` from the process environment. The passphrase file wins over the
    /// passphrase variable because an env var is readable by every process of the same user.
    pub fn from_env() -> Options {
        Self::from_map(|k| std::env::var(k).ok())
    }

    /// The same parsing over any key/value source (`from_env` is this plus the process env),
    /// so the rules — file beats variable, empty means unset — are testable without touching
    /// the process environment.
    pub fn from_map(get: impl Fn(&str) -> Option<String>) -> Options {
        let env = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let key = env(ENV_KEY).and_then(|v| secretbox::parse_key(&v).ok());
        let passphrase = env(ENV_PASSPHRASE_FILE)
            .and_then(|p| fs::read_to_string(p).ok())
            .or_else(|| env(ENV_PASSPHRASE))
            .map(|p| p.trim_end_matches(['\n', '\r']).to_string())
            .filter(|p| !p.is_empty());
        Options {
            backend: env(ENV_BACKEND).and_then(|v| Backend::parse(&v)),
            key,
            passphrase,
            iterations: env(ENV_ITERATIONS).and_then(|v| v.parse().ok()).unwrap_or(0),
            require_encryption: env(ENV_REQUIRE).is_some_and(|v| !matches!(v.trim(), "0" | "false" | "no")),
            keyring_tool: None,
            creds_tool: None,
        }
    }

    fn rounds(&self) -> u32 {
        if self.iterations == 0 {
            secretbox::DEFAULT_ITERATIONS
        } else {
            self.iterations
        }
    }
}

/// What `seagent secrets backend` and the doctor print.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    /// The ciphertext file (`secrets.enc` when it exists).
    pub path: PathBuf,
    pub backend: Backend,
    /// A plaintext `secrets.toml` is still present next to the store.
    pub legacy_present: bool,
    pub secrets: usize,
    pub notes: Vec<String>,
}

/// The decrypted store. Owned by the daemon; never handed to a VM or a tool.
pub struct Store {
    path: PathBuf,
    legacy: PathBuf,
    backend: Backend,
    /// PBKDF2 salt (empty for raw-key backends).
    salt: Vec<u8>,
    iterations: u32,
    key: Vec<u8>,
    secrets: BTreeMap<String, String>,
    notes: Vec<String>,
    opts: Options,
}

impl std::fmt::Debug for Store {
    /// Never print keys or values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).field("backend", &self.backend).field("secrets", &self.secrets.len()).finish()
    }
}

/// `secrets.toml` → `secrets.enc`.
pub fn store_path(plaintext: &Path) -> PathBuf {
    plaintext.with_extension(STORE_SUFFIX)
}

/// `secrets.toml` → `secrets.key` (the sealed data key for the tpm backend).
fn key_path(plaintext: &Path) -> PathBuf {
    plaintext.with_extension(KEY_SUFFIX)
}

/// On-disk header. Everything except `nonce`/`ciphertext` is authenticated as AAD.
#[derive(Debug, Serialize, Deserialize)]
struct Header {
    version: u32,
    backend: String,
    /// `pbkdf2-hmac-sha256` or `raw` (key held by keyring/TPM/env).
    kdf: String,
    #[serde(default)]
    iterations: u32,
    #[serde(default)]
    salt: String,
    nonce: String,
    ciphertext: String,
}

const STORE_VERSION: u32 = 1;

fn aad(backend: Backend, kdf: &str, iterations: u32, salt: &str) -> Vec<u8> {
    format!("seagent-secret-store-v{STORE_VERSION}|{}|{kdf}|{iterations}|{salt}", backend.as_str()).into_bytes()
}

fn tool(opts: &Options, which: KeyringTool) -> Option<PathBuf> {
    let (override_path, name) = match which {
        KeyringTool::SecretService => (opts.keyring_tool.clone(), "secret-tool"),
        KeyringTool::SystemdCreds => (opts.creds_tool.clone(), "systemd-creds"),
    };
    if let Some(p) = override_path {
        // An override that does not exist behaves like "not installed": that is how tests and
        // `SEAGENT_VAULT_*` overrides say "this backend is not usable here".
        return (p.is_file() && is_executable(&p)).then_some(p);
    }
    which_on_path(name)
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file() && is_executable(p))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// No execute bit: an existing file is runnable as far as the store is concerned.
#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// The OS key holder for the `keyring` backend (see `keyring.rs`). A configured stand-in
/// `secret-tool` that does not exist means "not usable here", as for the other tools.
fn keyring_holder(opts: &Options, store: &Path) -> Option<keyring::Holder> {
    match &opts.keyring_tool {
        Some(_) => tool(opts, KeyringTool::SecretService).map(|t| keyring::Holder::SecretTool(t)),
        None => keyring::holder(None, which_on_path, store),
    }
}

#[derive(Clone, Copy)]
enum KeyringTool {
    SecretService,
    SystemdCreds,
}

/// Is the `tpm` backend usable right now (tool present *and* a TPM device that systemd-creds
/// can talk to)? Checked by capability detection and by `seagent secrets backend`.
pub fn tpm_available(opts: &Options) -> bool {
    tool(opts, KeyringTool::SystemdCreds).is_some()
        && ["/dev/tpmrm0", "/dev/tpm0"].iter().any(|d| Path::new(d).exists())
}

/// May the TPM be picked *automatically*? For an unprivileged user `systemd-creds` asks
/// polkit for authorisation on every seal/unseal, i.e. a password dialog each time the vault
/// opens (and in every test that opens one). Only a root service gets it silently; other
/// users can still choose it explicitly with `SEAGENT_VAULT_BACKEND=tpm` (§0: no prompt storms).
fn tpm_without_prompt() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Is the `keyring` backend usable (the libsecret CLI, which needs a session bus to work;
/// the Keychain CLI on macOS; DPAPI on Windows)?
pub fn keyring_available(opts: &Options) -> bool {
    // The CLI alone is not enough: Secret Service lives on the session D-Bus, which a headless
    // or SSH login does not have (secret-tool then fails with "Cannot spawn a message bus").
    // A configured stand-in tool (tests) is taken as is.
    keyring_holder(opts, Path::new("")).is_some_and(|h| !h.needs_session_bus() || opts.keyring_tool.is_some() || session_bus())
}

fn session_bus() -> bool {
    std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok_and(|v| !v.trim().is_empty())
        || std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|d| Path::new(&d).join("bus").exists())
}

impl Store {
    /// A vault that lives only in memory (`Vault::empty()`): nothing is written, nothing is
    /// read, no key is ever needed. Every test and every read-only surface uses this.
    pub fn in_memory() -> Store {
        Store { path: PathBuf::new(), legacy: PathBuf::new(), backend: Backend::Plaintext, salt: vec![], iterations: 0, key: vec![], secrets: BTreeMap::new(), notes: vec![], opts: Options::default() }
    }

    /// The decrypted map, for placeholder substitution / redaction / leak checks.
    pub fn map(&self) -> &BTreeMap<String, String> {
        &self.secrets
    }

    /// Open (or lazily create) the store for `plaintext` (`…/secrets.toml`).
    pub fn open(plaintext: &Path, opts: &Options) -> Result<Store, String> {
        let path = store_path(plaintext);
        if path.exists() {
            return Self::open_encrypted(plaintext, &path, opts);
        }
        let mut notes = vec![];
        let (secrets, had_plain) = match fs::read_to_string(plaintext) {
            Ok(text) => (parse_plaintext(plaintext, &text)?, true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (BTreeMap::new(), false),
            Err(e) => return Err(format!("{}: {e}", plaintext.display())),
        };
        let backend = pick_backend(plaintext, opts, &mut notes)?;
        let mut store = Store {
            path,
            legacy: plaintext.to_path_buf(),
            backend,
            salt: Vec::new(),
            iterations: 0,
            key: Vec::new(),
            secrets,
            notes,
            opts: opts.clone(),
        };
        if had_plain {
            if backend.encrypted() {
                // Prepare key material, then the migration write verifies itself.
                store.prepare_key(true)?;
                store.save()?;
                store.verify_readback()?;
                store.shred_plaintext();
                store.notes.push(format!("{} was migrated to {} ({}), the plaintext file was removed", plaintext.display(), store.path.display(), backend.as_str()));
            } else {
                store.notes.push(format!("secrets stay in plaintext at {} — no key source (keyring, TPM, passphrase, {}); see `seagent secrets backend`", plaintext.display(), ENV_KEY));
                #[cfg(unix)]
                {
                    let mode = fs::metadata(plaintext).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
                    if mode & 0o077 != 0 {
                        return Err(format!("{} must not be readable by group/others (chmod 600)", plaintext.display()));
                    }
                }
                // No mode bits to check: make the plaintext file owner-only instead (an
                // explicit error when that fails, never a silently readable file).
                #[cfg(not(unix))]
                seagent_core::platform::fs_private::set_private(plaintext).map_err(|e| format!("{} could not be made private to this account: {e}", plaintext.display()))?;
            }
        }
        Ok(store)
    }

    fn open_encrypted(plaintext: &Path, path: &Path, opts: &Options) -> Result<Store, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let h: Header = toml::from_str(&text).map_err(|e| format!("{}: not an seagent secret store ({e})", path.display()))?;
        if h.version != STORE_VERSION {
            return Err(format!("{}: store version {} is newer than this seagent ({}); upgrade seagent", path.display(), h.version, STORE_VERSION));
        }
        let backend = Backend::parse(&h.backend).ok_or_else(|| format!("{}: unknown backend `{}`", path.display(), h.backend))?;
        let mut store = Store {
            path: path.to_path_buf(),
            legacy: plaintext.to_path_buf(),
            backend,
            salt: if h.salt.is_empty() { Vec::new() } else { b64decode(&h.salt)? },
            iterations: h.iterations,
            key: Vec::new(),
            secrets: BTreeMap::new(),
            notes: vec![],
            opts: opts.clone(),
        };
        store.key = store.unlock()?;
        let plain = secretbox::open(&store.key, &aad(backend, &h.kdf, h.iterations, &h.salt), &b64decode(&h.nonce)?, &b64decode(&h.ciphertext)?)?;
        let text = String::from_utf8(plain).map_err(|_| "the store did not decrypt to UTF-8".to_string())?;
        store.secrets = parse_plaintext(path, &text)?;
        if store.legacy.exists() {
            store.notes.push(format!("a plaintext {} is still present next to the store; `seagent secrets migrate` folds it in and removes it", store.legacy.display()));
        }
        Ok(store)
    }

    /// Obtain the key for an existing store, from the source its header names.
    fn unlock(&self) -> Result<Vec<u8>, String> {
        match self.backend {
            Backend::Plaintext => Err(format!("{}: a plaintext store has no key", self.path.display())),
            Backend::Env => self.opts.key.map(|k| k.to_vec()).ok_or_else(|| format!("{ENV_KEY} is not set (32 bytes, hex or base64); the store {} needs it", self.path.display())),
            Backend::Passphrase => {
                let pw = self.opts.passphrase.clone().ok_or_else(|| format!("the store {} is passphrase-protected; set {ENV_PASSPHRASE_FILE} (or {ENV_PASSPHRASE})", self.path.display()))?;
                secretbox::derive_key(&pw, &self.salt, self.iterations).map(|k| k.to_vec())
            }
            Backend::Keyring => {
                let t = keyring_holder(&self.opts, &self.path).ok_or_else(|| format!("{}, so the keyring store cannot be opened", keyring::missing()))?;
                let detail = |e: String| if e.trim().is_empty() { String::new() } else { format!(" ({})", e.trim()) };
                let account = keyring_account(&self.path);
                let found = |service: &str, account: &str| t.lookup(service, account).ok().filter(|s| !s.trim().is_empty());
                if found(KEYRING_SERVICE, &account).is_none() {
                    if let Some(old) = found(LEGACY_KEYRING_SERVICE, &keyring_account(&legacy_store_path(&self.path))) {
                        // Pre-rename entry: copy it under the current name (the old one stays).
                        let _ = t.store(&account, old.trim());
                        return secretbox::parse_key(old.trim()).map(|k| k.to_vec());
                    }
                }
                let s = t.lookup(KEYRING_SERVICE, &account).map_err(|e| {
                    if e.contains("non-UTF-8") {
                        e
                    } else {
                        format!("no keyring entry for {} — the key was deleted or the login keyring is locked{}", self.path.display(), detail(e))
                    }
                })?;
                if s.trim().is_empty() {
                    return Err(format!("no keyring entry for {} — the key was deleted or the login keyring is locked", self.path.display()));
                }
                secretbox::parse_key(s.trim()).map(|k| k.to_vec())
            }
            Backend::Tpm => {
                let t = tool(&self.opts, KeyringTool::SystemdCreds).ok_or_else(|| "systemd-creds is not installed, so the TPM-sealed key cannot be unsealed".to_string())?;
                let sealed = self.path.with_extension(KEY_SUFFIX);
                let data = fs::read(&sealed).map_err(|e| format!("{}: {e} (the TPM-sealed key is missing)", sealed.display()))?;
                // Feed the sealed blob on stdin and read the unsealed hex on stdout.
                // A key sealed before the rename carries the old credential name.
                let out = run_with_input(&t, &["decrypt", "--name", CREDS_NAME, "-", "-"], &data)
                    .or_else(|e| run_with_input(&t, &["decrypt", "--name", LEGACY_CREDS_NAME, "-", "-"], &data).map_err(|_| e))
                    .map_err(|e| format!("systemd-creds could not unseal the store key: {e}"))?;
                let s = String::from_utf8(out).map_err(|_| "systemd-creds returned non-UTF-8 data".to_string())?;
                secretbox::parse_key(s.trim()).map(|k| k.to_vec())
            }
        }
    }

    /// Create the key material for a *new* store (or the first encrypted write).
    fn prepare_key(&mut self, provisioning: bool) -> Result<(), String> {
        match self.backend {
            Backend::Plaintext => Ok(()),
            Backend::Env => {
                self.key = self.opts.key.map(|k| k.to_vec()).ok_or_else(|| format!("{ENV_KEY} is not set; it must hold 32 bytes as hex or base64"))?;
                Ok(())
            }
            Backend::Passphrase => {
                let pw = self.opts.passphrase.clone().ok_or_else(|| format!("set {ENV_PASSPHRASE_FILE} (a 0600 file holding the passphrase) or {ENV_PASSPHRASE}"))?;
                self.salt = secretbox::random_salt()?.to_vec();
                self.iterations = self.opts.rounds();
                self.key = secretbox::derive_key(&pw, &self.salt, self.iterations)?.to_vec();
                Ok(())
            }
            Backend::Keyring => {
                let t = keyring_holder(&self.opts, &self.path).ok_or_else(|| keyring::missing().to_string())?;
                let account = keyring_account(&self.path);
                if let Ok(s) = t.lookup(KEYRING_SERVICE, &account) {
                    if !s.trim().is_empty() {
                        self.key = secretbox::parse_key(s.trim())?.to_vec();
                        return Ok(());
                    }
                }
                if !provisioning {
                    return Err("no keyring entry and this is not a new store".into());
                }
                let key = secretbox::random_key()?;
                t.store(&account, &secretbox::hex(&key))?;
                self.key = key.to_vec();
                Ok(())
            }
            Backend::Tpm => {
                let t = tool(&self.opts, KeyringTool::SystemdCreds).ok_or_else(|| "systemd-creds is not installed (and the TPM backend needs it)".to_string())?;
                let sealed = self.path.with_extension(KEY_SUFFIX);
                if sealed.exists() {
                    let data = fs::read(&sealed).map_err(|e| e.to_string())?;
                    let out = run_with_input(&t, &["decrypt", "--name", CREDS_NAME, "-", "-"], &data)?;
                    let s = String::from_utf8(out).map_err(|_| "systemd-creds returned non-UTF-8 data".to_string())?;
                    self.key = secretbox::parse_key(s.trim())?.to_vec();
                    return Ok(());
                }
                if !provisioning {
                    return Err(format!("{} is missing and this is not a new store", sealed.display()));
                }
                let key = secretbox::random_key()?;
                let out = run_with_input(&t, &["encrypt", "--name", CREDS_NAME, "--with-key=tpm2", "-", "-"], secretbox::hex(&key).as_bytes())?;
                write_private(&sealed, &out)?;
                self.notes.push(format!("sealed a new store key to the TPM in {}", sealed.display()));
                self.key = key.to_vec();
                Ok(())
            }
        }
    }

    pub fn names(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(String::as_str)
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    pub fn status(&self) -> Status {
        Status { path: self.path.clone(), backend: self.backend, legacy_present: self.legacy.exists(), secrets: self.secrets.len(), notes: self.notes.clone() }
    }

    pub fn set(&mut self, name: &str, value: &str) -> Result<(), String> {
        if !valid_name(name) {
            return Err("secret names are [A-Za-z0-9_] only".into());
        }
        let before = self.secrets.insert(name.to_string(), value.to_string());
        if let Err(e) = self.save() {
            // Do not leave memory and disk disagreeing.
            match before {
                Some(old) => self.secrets.insert(name.to_string(), old),
                None => self.secrets.remove(name),
            };
            return Err(e);
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<bool, String> {
        let before = self.secrets.remove(name);
        if before.is_none() {
            return Ok(false);
        }
        if let Err(e) = self.save() {
            if let Some(old) = before {
                self.secrets.insert(name.to_string(), old);
            }
            return Err(e);
        }
        Ok(true)
    }

    /// Write the store. Encrypted files are created 0600 atomically; the key is provisioned on
    /// the first write only, so reading an untouched config never spawns a keyring/TPM tool.
    pub fn save(&mut self) -> Result<(), String> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let payload = toml::to_string(&self.secrets.iter().map(|(k, v)| (k.clone(), toml::Value::String(v.clone()))).collect::<toml::Table>()).map_err(|e| e.to_string())?;
        if !self.backend.encrypted() {
            write_private(&self.legacy, payload.as_bytes())?;
            return Ok(());
        }
        if self.key.is_empty() {
            self.prepare_key(true)?;
        }
        let (kdf, salt) = match self.backend {
            Backend::Passphrase => ("pbkdf2-hmac-sha256", self.salt.clone()),
            _ => ("raw", Vec::new()),
        };
        let salt_b64 = b64encode(&salt);
        let aad = aad(self.backend, kdf, self.iterations, &salt_b64);
        let (nonce, ct) = secretbox::seal(&self.key, &aad, payload.as_bytes())?;
        let h = Header { version: STORE_VERSION, backend: self.backend.as_str().into(), kdf: kdf.into(), iterations: self.iterations, salt: salt_b64, nonce: b64encode(&nonce), ciphertext: b64encode(&ct) };
        let mut text = String::from("# seagent secret store — encrypted, do not edit. `seagent secrets backend` explains the key source.\n");
        text.push_str(&toml::to_string(&h).map_err(|e| e.to_string())?);
        write_private(&self.path, text.as_bytes())?;
        Ok(())
    }

    /// Read the file back and compare: migration only deletes the plaintext after this passes.
    fn verify_readback(&self) -> Result<(), String> {
        let text = fs::read_to_string(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        let h: Header = toml::from_str(&text).map_err(|e| format!("{}: {e}", self.path.display()))?;
        let plain = secretbox::open(&self.key, &aad(self.backend, &h.kdf, h.iterations, &h.salt), &b64decode(&h.nonce)?, &b64decode(&h.ciphertext)?)?;
        let back = parse_plaintext(&self.path, std::str::from_utf8(&plain).map_err(|_| "read-back is not UTF-8".to_string())?)?;
        if back != self.secrets {
            return Err(format!("{} did not read back identically; the plaintext file was kept", self.path.display()));
        }
        Ok(())
    }

    /// Overwrite the plaintext file with zeros, then remove it. Best effort: the ciphertext is
    /// already verified at this point, so a failure here is reported, not fatal.
    fn shred_plaintext(&mut self) {
        if !self.legacy.exists() {
            return;
        }
        let len = fs::metadata(&self.legacy).map(|m| m.len() as usize).unwrap_or(0);
        match fs::OpenOptions::new().write(true).open(&self.legacy) {
            Ok(mut f) => {
                let _ = f.write_all(&vec![0u8; len]);
                let _ = f.sync_all();
            }
            Err(e) => self.notes.push(format!("could not overwrite {} ({e})", self.legacy.display())),
        }
        match fs::remove_file(&self.legacy) {
            Ok(()) => {}
            Err(e) => {
                self.notes.push(format!("could not remove {} ({e}); delete it by hand", self.legacy.display()));
                // A plaintext file left behind must at least stay private.
                let _ = seagent_core::platform::fs_private::set_private(&self.legacy);
            }
        }
    }
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_plaintext(path: &Path, text: &str) -> Result<BTreeMap<String, String>, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("{}: {e}", path.display()))?;
    let mut map = BTreeMap::new();
    for (k, v) in table {
        match v.as_str() {
            Some(s) => {
                map.insert(k, s.to_string());
            }
            None => return Err(format!("secret `{k}` must be a string")),
        }
    }
    Ok(map)
}

fn pick_backend(plaintext: &Path, opts: &Options, notes: &mut Vec<String>) -> Result<Backend, String> {
    if let Some(b) = opts.backend {
        return match b {
            Backend::Keyring if !keyring_available(opts) => Err(if cfg!(any(target_os = "macos", windows, target_os = "android", target_os = "ios")) && opts.keyring_tool.is_none() {
                format!("the keyring backend is not usable here: {}; use passphrase or env", keyring::missing())
            } else {
                "the keyring backend needs the secret-tool CLI (apt install libsecret-tools) and a desktop login session (D-Bus); on a server use tpm or passphrase".into()
            }),
            Backend::Tpm if !tpm_available(opts) && !cfg!(target_os = "linux") => Err(format!("the tpm backend is Linux-only (systemd-creds --with-key=tpm2) and not available on {}; use keyring, passphrase or env", std::env::consts::OS)),
            Backend::Tpm if !tpm_available(opts) => Err(format!("the tpm backend needs systemd-creds and a TPM device; {} is not usable here", key_path(plaintext).display())),
            Backend::Env if opts.key.is_none() => Err(format!("{ENV_KEY} is not set (32 bytes, hex or base64)")),
            Backend::Passphrase if opts.passphrase.is_none() => Err(format!("set {ENV_PASSPHRASE_FILE} (a 0600 file holding the passphrase) or {ENV_PASSPHRASE}")),
            other => Ok(other),
        };
    }
    let detected = if opts.key.is_some() {
        Some(Backend::Env)
    } else if keyring_available(opts) {
        Some(Backend::Keyring)
    } else if tpm_available(opts) && tpm_without_prompt() {
        Some(Backend::Tpm)
    } else if opts.passphrase.is_some() {
        Some(Backend::Passphrase)
    } else {
        None
    };
    match detected {
        Some(b) => Ok(b),
        None if opts.require_encryption => Err(format!(
            "no key source: install libsecret-tools (keyring), expose a TPM (systemd-creds), or set {ENV_PASSPHRASE_FILE} / {ENV_KEY}. {ENV_REQUIRE}=1 forbids the plaintext fallback"
        )),
        None => {
            notes.push(format!("no key source found; secrets stay in the 0600 plaintext file. Install libsecret-tools, enable a TPM, or set {ENV_PASSPHRASE_FILE} to encrypt them"));
            Ok(Backend::Plaintext)
        }
    }
}

/// Explicit migration of an existing plaintext file (what `seagent secrets migrate` runs). Returns
/// the number of secrets moved and the backend that now holds them.
pub fn migrate(plaintext: &Path, opts: &Options) -> Result<(usize, Backend, Vec<String>), String> {
    let text = match fs::read_to_string(plaintext) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && store_path(plaintext).exists() => {
            return Err(format!("{} is already encrypted into {} — nothing to migrate", plaintext.display(), store_path(plaintext).display()))
        }
        Err(e) => return Err(format!("{}: {e}", plaintext.display())),
    };
    let secrets = parse_plaintext(plaintext, &text)?;
    let mut notes = vec![];
    let backend = pick_backend(plaintext, opts, &mut notes)?;
    if !backend.encrypted() {
        return Err(notes.join("; ") + " — nothing to migrate to");
    }
    let mut store = Store {
        path: store_path(plaintext),
        legacy: plaintext.to_path_buf(),
        backend,
        salt: Vec::new(),
        iterations: 0,
        key: Vec::new(),
        secrets,
        notes,
        opts: opts.clone(),
    };
    if store.path.exists() {
        // Merge: secrets already in the store win, then the plaintext is shredded.
        let existing = Store::open_encrypted(plaintext, &store.path, opts)?;
        for (k, v) in existing.secrets {
            store.secrets.insert(k, v);
        }
    }
    store.prepare_key(true)?;
    store.save()?;
    store.verify_readback()?;
    store.shred_plaintext();
    let n = store.secrets.len();
    let notes = store.notes.clone();
    Ok((n, backend, notes))
}

/// Re-encrypt the store under a fresh key (ent-085): a new passphrase (and salt), a new
/// `SEAGENT_VAULT_KEY`, a new keyring entry / TPM-sealed data key, or a different backend
/// altogether (`new.backend`). The old store is opened with `old`; the new file is written,
/// read back and compared before anything of the old key material is dropped, and the previous
/// ciphertext is restored if any step fails.
pub fn rekey(plaintext: &Path, old: &Options, new: &Options) -> Result<(usize, Backend, Vec<String>), String> {
    let mut store = Store::open(plaintext, old)?;
    if !store.backend.encrypted() {
        return Err("the store is plaintext — run `seagent secrets migrate` first".into());
    }
    let mut notes = vec![];
    let backend = if new.backend.is_some() { pick_backend(plaintext, new, &mut notes)? } else { store.backend };
    if !backend.encrypted() {
        return Err("rekeying to plaintext is not allowed".into());
    }
    let previous = fs::read(&store.path).map_err(|e| format!("{}: {e}", store.path.display()))?;
    let sealed = key_path(plaintext);
    let sealed_bak = sealed.with_extension("key.prev");
    store.backend = backend;
    store.opts = new.clone();
    store.key.clear();
    store.salt.clear();
    store.iterations = 0;
    let result = (|| -> Result<(), String> {
        match backend {
            Backend::Keyring => {
                let t = keyring_holder(&store.opts, &store.path).ok_or_else(|| keyring::missing().to_string())?;
                let key = secretbox::random_key()?;
                t.store(&keyring_account(&store.path), &secretbox::hex(&key))?;
                store.key = key.to_vec();
            }
            Backend::Tpm => {
                if sealed.exists() {
                    fs::rename(&sealed, &sealed_bak).map_err(|e| e.to_string())?;
                }
                store.prepare_key(true)?;
            }
            _ => store.prepare_key(true)?,
        }
        store.save()?;
        store.verify_readback()
    })();
    if let Err(e) = result {
        let _ = write_private(&store.path, &previous);
        if sealed_bak.exists() {
            let _ = fs::rename(&sealed_bak, &sealed);
        }
        return Err(format!("rekey failed, the previous store was restored: {e}"));
    }
    let _ = fs::remove_file(&sealed_bak);
    notes.extend(store.notes.clone());
    Ok((store.secrets.len(), backend, notes))
}

/// The backend recorded in an existing store, read from the header only: no key, no KDF, no
/// subprocess. `seagent status` must stay instant and must not unlock anything.
pub fn peek_backend(plaintext: &Path) -> Option<Backend> {
    #[derive(Deserialize)]
    struct Peek {
        backend: String,
        #[serde(default)]
        version: u32,
    }
    let text = fs::read_to_string(store_path(plaintext)).ok()?;
    let p: Peek = toml::from_str(&text).ok()?;
    (p.version == STORE_VERSION).then(|| Backend::parse(&p.backend)).flatten()
}

/// Read-only status for `seagent doctor` / `seagent secrets backend`.
pub fn status(plaintext: &Path, opts: &Options) -> Status {
    let enc = store_path(plaintext);
    if enc.exists() {
        match Store::open(plaintext, opts) {
            Ok(s) => s.status(),
            Err(e) => Status { path: enc, backend: Backend::Plaintext, legacy_present: plaintext.exists(), secrets: 0, notes: vec![e] },
        }
    } else {
        let n = fs::read_to_string(plaintext).ok().and_then(|t| t.parse::<toml::Table>().ok()).map(|t| t.len()).unwrap_or(0);
        let mut notes = vec![];
        let backend = pick_backend(plaintext, opts, &mut notes).unwrap_or(Backend::Plaintext);
        Status { path: plaintext.to_path_buf(), backend, legacy_present: plaintext.exists(), secrets: n, notes }
    }
}

fn keyring_account(store: &Path) -> String {
    // Stable across moves of the config dir only if the path is stable; that is the point:
    // two SEAGENT_HOMEs must not share a keyring entry.
    format!("vault:{}", store.display())
}

fn store_in_keyring(tool: &Path, account: &str, secret: &str) -> Result<(), String> {
    let mut child = Command::new(tool)
        .args(["store", "--label=seagent secret store", "service", KEYRING_SERVICE, "account", account])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", tool.display()))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(secret.as_bytes()).and_then(|_| si.write_all(b"\n")).map_err(|e| format!("secret-tool: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("secret-tool: {e}"))?;
    if !out.status.success() {
        return Err(format!("secret-tool store failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn run(tool: &Path, args: &[&str], _unused: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let out = Command::new(tool).args(args).stdin(Stdio::null()).output().map_err(|e| format!("{}: {e}", tool.display()))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(out.stdout)
}

fn run_with_input(tool: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(tool).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{}: {e}", tool.display()))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(input).map_err(|e| format!("{}: {e}", tool.display()))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("{}: {e}", tool.display()))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(out.stdout)
}

fn b64encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn b64decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|_| "the store file is damaged (bad base64)".to_string())
}

/// Atomic write with mode 0600 from creation (never a window where the file is readable).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    crate::util::atomic_write(path, bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
    }
    // Windows: the protected owner-only DACL (the parent is the per-user profile directory).
    #[cfg(not(unix))]
    {
        seagent_core::platform::fs_private::set_private(path).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[cfg(unix)] // stand-in tools are `#!/bin/sh` scripts; modes are checked
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir() -> seagent_core::tmp::TempDir {
        seagent_core::tmp::TempDir::new("seagent-secretstore")
    }

    /// No backend can be detected: both helper tools point at a path that does not exist.
    fn bare_opts() -> Options {
        Options { keyring_tool: Some(PathBuf::from("/nonexistent/secret-tool")), creds_tool: Some(PathBuf::from("/nonexistent/systemd-creds")), ..Default::default() }
    }

    fn passphrase_opts() -> Options {
        Options { backend: Some(Backend::Passphrase), passphrase: Some("correct horse battery".into()), iterations: 120_000, keyring_tool: Some(PathBuf::from("/nonexistent/secret-tool")), creds_tool: Some(PathBuf::from("/nonexistent/systemd-creds")), ..Default::default() }
    }

    /// A stand-in for `secret-tool`: `store` writes stdin to `<dir>/entry`, `lookup` prints it.
    fn fake_secret_tool(dir: &Path) -> PathBuf {
        let p = dir.join("secret-tool");
        let entry = dir.join("entry");
        fs::write(&p, format!("#!/bin/sh\nset -e\ncase \"$1\" in\n  store) cat > '{}' ;;\n  lookup) [ -f '{}' ] && cat '{}' || exit 1 ;;\n  *) exit 2 ;;\nesac\n", entry.display(), entry.display(), entry.display())).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// ent-085: a new passphrase, a new raw key, a new keyring entry — and a failed rekey
    /// leaves the old store intact.
    #[test]
    fn rekey_rotates_the_master_key_and_restores_on_failure() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let mut s = Store::open(&p, &passphrase_opts()).unwrap();
        s.set("OPENAI_API_KEY", "sk-1").unwrap();
        let before = fs::read_to_string(d.join("secrets.enc")).unwrap();
        // Missing new passphrase: refused, old file byte-identical and still opens.
        let broken = Options { passphrase: None, ..passphrase_opts() };
        assert!(rekey(&p, &passphrase_opts(), &broken).is_err());
        let broken2 = Options { backend: None, passphrase: None, ..passphrase_opts() };
        assert!(rekey(&p, &passphrase_opts(), &broken2).unwrap_err().contains("restored"));
        assert_eq!(fs::read_to_string(d.join("secrets.enc")).unwrap(), before);
        // New passphrase: the old one no longer opens it, the new one does.
        let new = Options { passphrase: Some("new passphrase 2026".into()), ..passphrase_opts() };
        let (n, b, _) = rekey(&p, &passphrase_opts(), &new).unwrap();
        assert_eq!((n, b), (1, Backend::Passphrase));
        assert!(Store::open(&p, &passphrase_opts()).is_err());
        assert_eq!(Store::open(&p, &new).unwrap().get("OPENAI_API_KEY"), Some("sk-1"));
        // Switch backend: passphrase → env key.
        let env = Options { backend: Some(Backend::Env), key: Some([7u8; 32]), ..bare_opts() };
        assert_eq!(rekey(&p, &new, &env).unwrap().1, Backend::Env);
        assert_eq!(Store::open(&p, &env).unwrap().get("OPENAI_API_KEY"), Some("sk-1"));
        // Keyring (stand-in tool): a fresh key replaces the entry.
        let kr = Options { backend: Some(Backend::Keyring), keyring_tool: Some(fake_secret_tool(&d)), creds_tool: Some(PathBuf::from("/nonexistent")), ..Default::default() };
        rekey(&p, &env, &kr).unwrap();
        let k1 = fs::read_to_string(d.join("entry")).unwrap();
        rekey(&p, &kr, &Options { backend: None, ..kr.clone() }).unwrap();
        assert_ne!(fs::read_to_string(d.join("entry")).unwrap(), k1, "a new keyring key");
        assert_eq!(Store::open(&p, &kr).unwrap().get("OPENAI_API_KEY"), Some("sk-1"));
    }

    #[test]
    fn backend_names_and_explanations_roundtrip() {
        for b in [Backend::Keyring, Backend::Tpm, Backend::Passphrase, Backend::Env, Backend::Plaintext] {
            assert_eq!(Backend::parse(b.as_str()), Some(b));
            assert!(!b.explain().is_empty());
            assert_eq!(b.encrypted(), b != Backend::Plaintext);
        }
        assert_eq!(Backend::parse("TPM2"), Some(Backend::Tpm));
        assert_eq!(Backend::parse("nonsense"), None);
    }

    #[test]
    fn passphrase_store_reopens_with_the_header_kdf_params() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let mut s = Store::open(&p, &passphrase_opts()).unwrap();
        assert_eq!(s.backend(), Backend::Passphrase);
        s.set("TOKEN", "value-123456").unwrap();
        let header = fs::read_to_string(d.join("secrets.enc")).unwrap();
        assert!(header.contains("kdf = \"pbkdf2-hmac-sha256\"") && header.contains("backend = \"passphrase\""), "{header}");
        assert!(!header.contains("value-123456") && !header.contains("correct horse"));
        let again = Store::open(&p, &passphrase_opts()).unwrap();
        assert_eq!(again.get("TOKEN"), Some("value-123456"));
        // The wrong passphrase is refused, and the message points at the env var.
        let wrong = Options { passphrase: Some("wrong".into()), ..passphrase_opts() };
        assert!(Store::open(&p, &wrong).unwrap_err().contains("wrong key"));
        let missing = Options { passphrase: None, ..passphrase_opts() };
        assert!(Store::open(&p, &missing).unwrap_err().contains(ENV_PASSPHRASE_FILE));
    }

    #[test]
    fn header_downgrade_is_authenticated() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let mut s = Store::open(&p, &passphrase_opts()).unwrap();
        s.set("K", "value-123456").unwrap();
        let enc = d.join("secrets.enc");
        let text = fs::read_to_string(&enc).unwrap();
        let downgraded = text.replace("iterations = 120000", "iterations = 100000");
        assert_ne!(text, downgraded, "the header really carries the iteration count");
        fs::write(&enc, downgraded).unwrap();
        let e = Store::open(&p, &passphrase_opts()).unwrap_err();
        assert!(e.contains("wrong key"), "the iteration count is part of the AEAD header: {e}");
    }

    #[test]
    fn keyring_backend_uses_the_secret_service_cli() {
        let d = tmpdir();
        let tool = fake_secret_tool(&d);
        let p = d.join("secrets.toml");
        let opts = Options { backend: Some(Backend::Keyring), keyring_tool: Some(tool.clone()), creds_tool: Some(PathBuf::from("/nonexistent")), ..Default::default() };
        let mut s = Store::open(&p, &opts).unwrap();
        s.set("K", "value-123456").unwrap();
        let entry = fs::read_to_string(d.join("entry")).unwrap();
        assert_eq!(entry.trim().len(), 64, "the keyring holds a 32-byte key in hex");
        assert!(Store::open(&p, &opts).unwrap().get("K") == Some("value-123456"));
        // Losing the keyring entry is reported as such, not as a corrupt file.
        fs::remove_file(d.join("entry")).unwrap();
        assert!(Store::open(&p, &opts).unwrap_err().contains("no keyring entry"));
        // No secret-tool at all names the package to install.
        let none = Options { keyring_tool: Some(PathBuf::from("/nonexistent/secret-tool")), ..opts.clone() };
        assert!(Store::open(&p, &none).unwrap_err().contains("libsecret-tools"));
        let _ = tool;
    }

    #[test]
    #[ignore = "uses the real TPM via systemd-creds; for a non-root user that pops a polkit password dialog on every call"]
    fn tpm_backend_seals_the_key_when_the_machine_has_one() {        let d = tmpdir();
        let opts = Options { backend: Some(Backend::Tpm), iterations: 0, keyring_tool: Some(PathBuf::from("/nonexistent")), creds_tool: None, ..Default::default() };
        // No TPM on this machine: nothing to check (the stub test above covers the code path).
        if !tpm_available(&opts) {
            return;
        }
        let p = d.join("secrets.toml");
        let mut s = Store::open(&p, &opts).unwrap();
        s.set("K", "value-123456").unwrap();
        assert!(d.join("secrets.key").exists(), "the sealed data key sits next to the store");
        assert_eq!(fs::metadata(d.join("secrets.key")).unwrap().permissions().mode() & 0o777, 0o600);
        let enc = fs::read_to_string(d.join("secrets.enc")).unwrap();
        assert!(enc.contains("backend = \"tpm\"") && !enc.contains("value-123456"));
        assert_eq!(Store::open(&p, &opts).unwrap().get("K"), Some("value-123456"));
        // A sealed key that is not the one that wrote the store is refused.
        fs::write(d.join("secrets.key"), b"garbage").unwrap();
        assert!(Store::open(&p, &opts).is_err());
    }

    /// A stand-in for `systemd-creds`: seals/looks up a blob in a file under the test dir, so the
    /// TPM code path (spawn, argv, stdin/stdout, 0600 key file) is exercised without ever asking
    /// polkit for authorisation. The real-tool test is `#[ignore]`d above for the same reason.
    fn fake_creds(dir: &Path) -> PathBuf {
        let p = dir.join("systemd-creds");
        let sealed = dir.join("sealed");
        fs::write(
            &p,
            format!(
                "#!/bin/sh\nset -e\ncase \"$1\" in\n  encrypt) cat > '{}' ;;\n  decrypt) [ -f '{}' ] && cat '{}' || exit 1 ;;\n  *) exit 2 ;;\nesac\n",
                sealed.display(),
                sealed.display(),
                sealed.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn tpm_backend_seals_and_unseals_through_the_creds_tool() {
        let d = tmpdir();
        let tool = fake_creds(&d);
        let opts = Options { backend: Some(Backend::Tpm), keyring_tool: Some(PathBuf::from("/nonexistent/secret-tool")), creds_tool: Some(tool), ..Default::default() };
        let p = d.join("secrets.toml");
        let mut s = Store::open(&p, &opts).unwrap();
        s.set("K", "value-123456").unwrap();
        assert!(d.join("secrets.key").exists(), "the sealed data key sits next to the store");
        assert_eq!(fs::metadata(d.join("secrets.key")).unwrap().permissions().mode() & 0o777, 0o600);
        let enc = fs::read_to_string(d.join("secrets.enc")).unwrap();
        assert!(enc.contains("backend = \"tpm\"") && !enc.contains("value-123456"), "{enc}");
        assert_eq!(Store::open(&p, &opts).unwrap().get("K"), Some("value-123456"));
        // Without the TPM backend's sealed key nothing can be unsealed, and the error says so.
        fs::remove_file(d.join("secrets.key")).unwrap();
        let e = Store::open(&p, &opts).unwrap_err();
        assert!(e.contains("secrets.key"), "{e}");
    }

    #[test]
    fn tpm_is_not_auto_selected_for_a_non_root_user() {
        // §0: the TPM backend must never be picked on its own for an unprivileged user, because
        // `systemd-creds` would ask polkit (a password dialog) on every seal and unseal.
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let detected = status(&p, &Options::default()).backend;
        if unsafe { libc::geteuid() } == 0 {
            assert!(detected != Backend::Plaintext || !tpm_available(&Options::default()));
        } else {
            assert_ne!(detected, Backend::Tpm, "an unprivileged user must choose the tpm backend explicitly");
        }
        // Choosing it explicitly is still possible and names the requirement when unusable.
        let explicit = Options { backend: Some(Backend::Tpm), keyring_tool: Some(PathBuf::from("/nonexistent")), creds_tool: Some(PathBuf::from("/nonexistent/systemd-creds")), ..Default::default() };
        assert!(Store::open(&p, &explicit).unwrap_err().contains("systemd-creds"));
    }

    #[test]
    fn no_key_source_falls_back_to_plaintext_and_says_so() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let mut s = Store::open(&p, &bare_opts()).unwrap();
        assert_eq!(s.backend(), Backend::Plaintext);
        assert!(s.notes().iter().any(|n| n.contains("no key source")), "{:?}", s.notes());
        s.set("K", "value-123456").unwrap();
        assert!(p.exists() && !d.join("secrets.enc").exists());
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(Store::open(&p, &bare_opts()).unwrap().notes().iter().any(|n| n.contains("plaintext")));
    }

    #[test]
    fn require_encryption_turns_the_fallback_into_an_error() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let opts = Options { require_encryption: true, ..bare_opts() };
        let e = Store::open(&p, &opts).unwrap_err();
        assert!(e.contains("no key source") && e.contains(ENV_PASSPHRASE_FILE), "{e}");
        assert!(!p.exists());
    }

    #[test]
    fn explicit_migrate_merges_both_files_and_removes_the_plaintext() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let opts = Options { backend: Some(Backend::Env), key: Some([3u8; 32]), keyring_tool: Some(PathBuf::from("/nonexistent")), ..Default::default() };
        // An encrypted store already holds one key; the plaintext file holds another.
        Store::open(&p, &opts).unwrap().set("OLD", "old-value").unwrap();
        fs::write(&p, "NEW = \"new-value\"\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let (n, backend, notes) = migrate(&p, &opts).unwrap();
        assert_eq!((n, backend), (2, Backend::Env), "{notes:?}");
        assert!(!p.exists());
        let s = Store::open(&p, &opts).unwrap();
        assert_eq!(s.get("OLD"), Some("old-value"));
        assert_eq!(s.get("NEW"), Some("new-value"));
        // Nothing left to migrate is an error the CLI can print.
        assert!(migrate(&p, &opts).unwrap_err().contains("secrets.toml"));
    }

    #[test]
    fn env_options_prefer_the_passphrase_file_and_reject_empty_values() {
        let d = tmpdir();
        let f = d.join("pass");
        fs::write(&f, "from-file\n").unwrap();
        let map: BTreeMap<String, String> = [(ENV_PASSPHRASE_FILE, f.display().to_string()), (ENV_PASSPHRASE, "from-var".into()), (ENV_BACKEND, "passphrase".into()), (ENV_ITERATIONS, "120000".into()), (ENV_REQUIRE, "1".into())].into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let o = Options::from_map(|k| map.get(k).cloned());
        assert_eq!(o.passphrase.as_deref(), Some("from-file"));
        assert_eq!(o.backend, Some(Backend::Passphrase));
        assert_eq!(o.iterations, 120000);
        assert!(o.require_encryption);
        let empty: BTreeMap<String, String> = [(ENV_KEY, "  ".into())].into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let o = Options::from_map(|k| empty.get(k).cloned());
        assert!(o.key.is_none(), "a blank variable is not a key");
    }

    #[test]
    fn status_reports_a_missing_key_instead_of_pretending() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let opts = Options { backend: Some(Backend::Env), key: Some([5u8; 32]), keyring_tool: Some(PathBuf::from("/nonexistent")), ..Default::default() };
        Store::open(&p, &opts).unwrap().set("K", "value-123456").unwrap();
        let good = status(&p, &opts);
        assert_eq!((good.backend, good.secrets, good.legacy_present), (Backend::Env, 1, false));
        let bad = status(&p, &Options { key: Some([6u8; 32]), ..opts });
        assert!(bad.notes.iter().any(|n| n.contains("wrong key")), "{:?}", bad.notes);
        assert_eq!(bad.secrets, 0);
        // Plaintext file only: the status still counts what is there.
        let q = d.join("other.toml");
        fs::write(&q, "A = \"x\"\nB = \"y\"\n").unwrap();
        let st = status(&q, &bare_opts());
        assert_eq!((st.backend, st.secrets, st.legacy_present), (Backend::Plaintext, 2, true));
    }

    #[test]
    fn values_never_reach_the_header_or_a_readme_style_field() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let mut s = Store::open(&p, &passphrase_opts()).unwrap();
        s.set("API_KEY", "sk-live-0123456789").unwrap();
        let raw = fs::read(d.join("secrets.enc")).unwrap();
        for needle in [b"API_KEY".as_slice(), b"sk-live".as_slice(), b"correct horse".as_slice()] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle), "{} leaked", String::from_utf8_lossy(needle));
        }
    }
}
