//! Guest image manifest and lifecycle (plan B1/B3, §0-3; H11 for what is *not* in
//! the image).
//!
//! One microVM boots from exactly two host files: a kernel and an initramfs that
//! carries the guest agent as `/sbin/init`. `manifest.json` records the sha256 and
//! size of both, so a boot can never silently use a half-written or swapped
//! image, and a manifest version this crate does not speak is rebuilt instead of
//! booted.
//!
//! Building is delegated to `packaging/vm/build-image.sh` (it downloads the
//! Firecracker kernel and the Alpine minirootfs, packs the static agent in) and
//! only happens on an explicit `seagent sandbox vm image build` — never at boot, and
//! never from inside a guest. Nothing secret goes into the image: it is a public
//! kernel plus a public Alpine rootfs plus seagent's own agent, which is why a
//! compromised guest cannot read a key out of its own disk.

use crate::config::VmConfig;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Manifest file inside an image directory; its presence marks a built image.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Kernel file name inside an image directory (what the builder writes).
pub const KERNEL_FILE: &str = "vmlinux";
/// Initramfs file name inside an image directory.
pub const INITRAMFS_FILE: &str = "initramfs.cpio.gz";
/// Builder, relative to the repository root.
pub const BUILD_SCRIPT: &str = "packaging/vm/build-image.sh";
/// The same script inside an installed share dir (`<share>/vm/build-image.sh`).
pub const SHIPPED_SCRIPT: &str = "vm/build-image.sh";

/// One file of the image: its name inside the image directory, its digest and
/// its size. All three are verified on every load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
}

/// Everything needed to decide "is this image bootable, and with which agent?".
///
/// The on-disk shape is the one `build-image.sh` writes (nested `agent` and
/// `alpine` objects); [`ImageManifest`] flattens it for callers, and also accepts
/// the flat shape for hand-written manifests and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageManifest {
    pub image_version: u32,
    pub kernel: FileEntry,
    pub initramfs: FileEntry,
    /// sha256 of the `seagent-vm-guest` binary packed into the initramfs (recorded,
    /// not verifiable from here — the agent reports its version over the channel).
    pub agent_sha256: String,
    /// Alpine version the rootfs came from (`3.20.3`).
    pub alpine: String,
    pub built_at: String,
    /// What produced the image: the builder script, or the config/legacy path it
    /// was loaded from.
    pub source: String,
}

#[derive(Deserialize)]
struct RawAgent {
    #[serde(default)]
    sha256: String,
}

#[derive(Deserialize)]
struct RawAlpine {
    #[serde(default)]
    version: String,
}

/// `"alpine": "3.20.3"` (flat) or `"alpine": {"version": …}` (builder).
#[derive(Deserialize)]
#[serde(untagged)]
enum RawAlpineField {
    Version(String),
    Object(RawAlpine),
}

impl Default for RawAlpineField {
    fn default() -> Self {
        RawAlpineField::Version(String::new())
    }
}

#[derive(Deserialize)]
struct RawManifest {
    image_version: u32,
    kernel: FileEntry,
    initramfs: FileEntry,
    #[serde(default)]
    agent: Option<RawAgent>,
    #[serde(default)]
    agent_sha256: String,
    #[serde(default)]
    alpine: RawAlpineField,
    #[serde(default)]
    built_at: String,
    #[serde(default)]
    source: String,
}

impl From<RawManifest> for ImageManifest {
    fn from(r: RawManifest) -> Self {
        let agent_sha256 = if r.agent_sha256.is_empty() {
            r.agent.map(|a| a.sha256).unwrap_or_default()
        } else {
            r.agent_sha256
        };
        let alpine = match r.alpine {
            RawAlpineField::Version(v) => v,
            RawAlpineField::Object(o) => o.version,
        };
        let source = if r.source.is_empty() { BUILD_SCRIPT.to_string() } else { r.source };
        ImageManifest { image_version: r.image_version, kernel: r.kernel, initramfs: r.initramfs, agent_sha256, alpine, built_at: r.built_at, source }
    }
}

impl<'de> Deserialize<'de> for ImageManifest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        RawManifest::deserialize(d).map(ImageManifest::from)
    }
}

/// A verified image on disk: the manifest plus the directory its files live in.
#[derive(Debug, Clone)]
pub struct GuestImage {
    pub manifest: ImageManifest,
    pub dir: PathBuf,
}

impl GuestImage {
    /// Read `<dir>/manifest.json`, check the layout version and verify every
    /// digest and size against the files on disk.
    pub fn load(dir: &Path) -> Result<GuestImage, String> {
        let path = dir.join(MANIFEST_FILE);
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("guest image: cannot read {}: {e}; run `seagent sandbox vm image build`", path.display()))?;
        let manifest: ImageManifest = serde_json::from_str(&text)
            .map_err(|e| format!("guest image manifest {} is not valid: {e}; run `seagent sandbox vm image build`", path.display()))?;
        if manifest.image_version != crate::IMAGE_VERSION {
            return Err(format!(
                "guest image manifest {} is version {}, this seagent speaks version {}; run `seagent sandbox vm image build`",
                path.display(),
                manifest.image_version,
                crate::IMAGE_VERSION
            ));
        }
        for (label, entry) in [("kernel", &manifest.kernel), ("initramfs", &manifest.initramfs)] {
            if entry.path.is_empty() || Path::new(&entry.path).is_absolute() || entry.path.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
                return Err(format!("guest image manifest {}: {label} path `{}` must be a plain file name inside the image directory", path.display(), entry.path));
            }
            if !is_sha256_hex(&entry.sha256) {
                return Err(format!("guest image manifest {}: {label} sha256 must be 64 hex characters; run `seagent sandbox vm image build`", path.display()));
            }
        }
        let img = GuestImage { manifest, dir: dir.to_path_buf() };
        img.verify()?;
        Ok(img)
    }

    /// Re-hash the files and compare with the manifest. An error always names the
    /// offending file, because "the image is broken" is not actionable.
    pub fn verify(&self) -> Result<(), String> {
        for (label, entry) in [("kernel", &self.manifest.kernel), ("initramfs", &self.manifest.initramfs)] {
            let path = self.locate(entry);
            let meta = fs::metadata(&path).map_err(|e| {
                format!("guest image: {label} `{}` is missing ({e}); run `seagent sandbox vm image build`", path.display())
            })?;
            if meta.len() != entry.size {
                return Err(format!(
                    "guest image: {label} `{}` is {} bytes, manifest says {}; run `seagent sandbox vm image build`",
                    path.display(),
                    meta.len(),
                    entry.size
                ));
            }
            let actual = sha256_file(&path)?;
            if !actual.eq_ignore_ascii_case(&entry.sha256) {
                return Err(format!(
                    "guest image: {label} `{}` sha256 mismatch (manifest {}, on disk {actual}); run `seagent sandbox vm image build`",
                    path.display(),
                    entry.sha256
                ));
            }
        }
        Ok(())
    }

    /// Find the image to boot: `exec.vm.kernel`/`initramfs` when both are set,
    /// else `<root>/image`, else the legacy `<root>/kernel/` pair.
    ///
    /// A configured pair has no manifest (it predates one), so its manifest is
    /// synthesised from the files themselves — which still gives every caller a
    /// verified digest to log and compare.
    pub fn find(cfg: &VmConfig, data: &Path) -> Result<GuestImage, String> {
        if !cfg.kernel.is_empty() || !cfg.initramfs.is_empty() {
            if cfg.kernel.is_empty() || cfg.initramfs.is_empty() {
                return Err("exec.vm.kernel and exec.vm.initramfs must be set together (or neither, to use the built image)".into());
            }
            let kernel = cfg.kernel_path(data);
            let initramfs = cfg.initramfs_path(data);
            for (label, p) in [("kernel", &kernel), ("initramfs", &initramfs)] {
                if !p.is_file() {
                    return Err(format!(
                        "guest image: configured {label} `{}` does not exist; run `seagent sandbox vm image build` or fix exec.vm.{label}",
                        p.display()
                    ));
                }
            }
            return GuestImage::from_files(&kernel, &initramfs, "exec.vm.kernel");
        }

        let root = cfg.root(data);
        let image_dir = root.join("image");
        if image_dir.join(MANIFEST_FILE).is_file() {
            return GuestImage::load(&image_dir);
        }

        let kernel = cfg.kernel_path(data);
        let initramfs = cfg.initramfs_path(data);
        if kernel.is_file() && initramfs.is_file() {
            return GuestImage::from_files(&kernel, &initramfs, "legacy kernel dir");
        }

        Err(format!(
            "no guest image: nothing at {} or {}; run `seagent sandbox vm image build`",
            image_dir.join(MANIFEST_FILE).display(),
            kernel.display()
        ))
    }

    /// Build (or reuse) `<root>/image` through `packaging/vm/build-image.sh`.
    ///
    /// A valid image is reused unless `force`. The script's stdout is passed
    /// through only with `SEAGENT_VM_BUILD_VERBOSE=1`, so a normal build is one line
    /// of seagent output; its stderr is folded into the error when it fails.
    pub fn build(cfg: &VmConfig, data: &Path, force: bool) -> Result<GuestImage, String> {
        let out = cfg.root(data).join("image");
        if !force {
            if let Ok(img) = GuestImage::load(&out) {
                return Ok(img);
            }
        }
        let script = build_script_path();
        if !script.is_file() {
            return Err(format!(
                "guest image build script not found at {}; set SEAGENT_REPO_ROOT to the seagent checkout, or install seagent with its share/ directory (SEAGENT_SHARE_DIR)",
                script.display()
            ));
        }
        let out = std::path::absolute(&out).unwrap_or(out);
        fs::create_dir_all(&out).map_err(|e| format!("guest image: cannot create {}: {e}", out.display()))?;

        let verbose = std::env::var("SEAGENT_VM_BUILD_VERBOSE").map(|v| v == "1").unwrap_or(false);
        let mut cmd = Command::new("bash");
        cmd.arg(&script).arg("--out").arg(&out);
        if let Some(agent) = shipped_agent(&script) {
            cmd.arg("--agent").arg(agent);
        }
        cmd.stdout(if verbose { Stdio::inherit() } else { Stdio::null() });
        cmd.stderr(if verbose { Stdio::inherit() } else { Stdio::piped() });
        let output = cmd.output().map_err(|e| format!("guest image: cannot run {}: {e}", script.display()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            return Err(format!(
                "guest image build failed ({}): {}\n{}",
                script.display(),
                output.status,
                tail.join("\n")
            ));
        }
        GuestImage::load(&out).map_err(|e| format!("guest image build finished but produced no usable image: {e}"))
    }

    /// Kernel path this image boots.
    pub fn kernel(&self) -> PathBuf {
        self.locate(&self.manifest.kernel)
    }

    /// Initramfs path this image boots.
    pub fn initramfs(&self) -> PathBuf {
        self.locate(&self.manifest.initramfs)
    }

    fn locate(&self, entry: &FileEntry) -> PathBuf {
        let p = Path::new(&entry.path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.dir.join(p)
        }
    }

    /// A manifest for a pair of files that was not produced by the builder
    /// (configured paths, legacy layout). Digests come from the files, so the
    /// result verifies by construction.
    fn from_files(kernel: &Path, initramfs: &Path, source: &str) -> Result<GuestImage, String> {
        let dir = kernel.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let entry = |p: &Path| -> Result<FileEntry, String> {
            let meta = fs::metadata(p).map_err(|e| format!("guest image: {} is missing ({e})", p.display()))?;
            let path = match p.strip_prefix(&dir) {
                Ok(rel) if !rel.as_os_str().is_empty() => rel.to_string_lossy().into_owned(),
                _ => p.to_string_lossy().into_owned(),
            };
            Ok(FileEntry { path, sha256: sha256_file(p)?, size: meta.len() })
        };
        let manifest = ImageManifest {
            image_version: crate::IMAGE_VERSION,
            kernel: entry(kernel)?,
            initramfs: entry(initramfs)?,
            agent_sha256: String::new(),
            alpine: String::new(),
            built_at: String::new(),
            source: source.to_string(),
        };
        let img = GuestImage { manifest, dir };
        img.verify()?;
        Ok(img)
    }
}

/// Where the builder script is expected. Resolved at run time only (no build-directory path is
/// baked into the binary): `SEAGENT_REPO_ROOT` (an explicit override, also what tests and packagers
/// use), then the installed share dir (`$SEAGENT_SHARE_DIR`, `<exe>/../share/seagent`,
/// `/usr/{local/,}share/seagent`: `vm/build-image.sh`), then a checkout the binary runs from.
fn build_script_path() -> PathBuf {
    build_script_in(std::env::var_os("SEAGENT_REPO_ROOT").map(PathBuf::from), std::env::var_os("SEAGENT_SHARE_DIR").map(PathBuf::from), std::env::current_exe().ok().as_deref(), &["/usr/local/share/seagent", "/usr/share/seagent"]) // = seagent_core::layout::system::SHARE (seagent-vm stays dependency-free)
}

fn build_script_in(repo_root: Option<PathBuf>, share_env: Option<PathBuf>, exe: Option<&Path>, system: &[&str]) -> PathBuf {
    if let Some(r) = repo_root {
        return r.join(BUILD_SCRIPT);
    }
    let mut cands: Vec<PathBuf> = share_env.into_iter().collect();
    if let Some(bin) = exe.and_then(Path::parent) {
        cands.push(bin.join("../share/seagent"));
        cands.push(bin.join("../lib/seagent/share"));
        cands.push(bin.join("share"));
    }
    cands.extend(system.iter().map(PathBuf::from));
    if let Some(found) = cands.iter().map(|d| d.join(SHIPPED_SCRIPT)).find(|p| p.is_file()) {
        return found;
    }
    // A checkout the binary runs from: any ancestor of the executable that holds the script.
    if let Some(found) = exe.into_iter().flat_map(|e| e.ancestors().skip(1)).map(|d| d.join(BUILD_SCRIPT)).find(|p| p.is_file()) {
        return found;
    }
    PathBuf::from(BUILD_SCRIPT)
}

/// The guest agent shipped next to the shipped builder script (release tarballs carry a static
/// `seagent-vm-guest`, so building an image needs no Rust toolchain).
fn shipped_agent(script: &Path) -> Option<PathBuf> {
    let a = script.parent()?.join("seagent-vm-guest");
    a.is_file().then_some(a)
}

/// sha256 of a file as lowercase hex.
///
/// The file is read in chunks; `seagent_net::crypto::sha256` is a one-shot digest, so
/// the chunks are fed into one buffer (a guest image is ~10 MiB) instead of
/// pulling a second hashing crate into this one.
pub fn sha256_file(p: &Path) -> Result<String, String> {
    let mut f = fs::File::open(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut data = Vec::new();
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    Ok(hex(&seagent_net::crypto::sha256(&data)))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// A directory under `$TMPDIR` (never `/tmp`: the build sandbox sets TMPDIR).
    fn tmp_dir(tag: &str) -> PathBuf {
        let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("seagent-vm-image-{}-{n}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, contents).expect("write");
        p
    }

    fn manifest_json(kernel: &Path, initramfs: &Path) -> String {
        format!(
            r#"{{
  "image_version": 1,
  "built_at": "2026-01-01T00:00:00Z",
  "kernel": {{"path": "vmlinux", "sha256": "{}", "size": {}}},
  "initramfs": {{"path": "initramfs.cpio.gz", "sha256": "{}", "size": {}}}
}}"#,
            sha256_file(kernel).unwrap(),
            fs::metadata(kernel).unwrap().len(),
            sha256_file(initramfs).unwrap(),
            fs::metadata(initramfs).unwrap().len()
        )
    }

    #[test]
    fn a_wrong_sha256_is_refused_and_names_the_file() {
        let dir = tmp_dir("bad-sha");
        let kernel = write(&dir, KERNEL_FILE, b"a real kernel");
        let initramfs = write(&dir, INITRAMFS_FILE, b"a real initramfs");
        let mut json = manifest_json(&kernel, &initramfs);
        // Corrupt only the kernel digest (valid hex, wrong content).
        let good = sha256_file(&kernel).unwrap();
        let bad = "0".repeat(64);
        json = json.replacen(&good, &bad, 1);
        write(&dir, MANIFEST_FILE, json.as_bytes());

        let err = GuestImage::load(&dir).expect_err("a wrong digest must not load");
        assert!(err.contains(KERNEL_FILE), "the error must name the broken file: {err}");
        assert!(err.contains("sha256"), "the error must say what is wrong: {err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_on_an_empty_dir_says_how_to_build_one() {
        let data = tmp_dir("empty");
        let cfg = VmConfig::default();
        let err = GuestImage::find(&cfg, &data).expect_err("no image");
        assert!(err.contains("seagent sandbox vm image build"), "actionable: {err}");
        let _ = fs::remove_dir_all(&data);
    }

    #[test]
    fn sha256_file_matches_the_known_digest_of_abc() {
        let dir = tmp_dir("sha");
        let p = write(&dir, "abc", b"abc");
        assert_eq!(sha256_file(&p).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_builder_script_is_found_in_the_installed_share_dir() {
        let root = tmp_dir("share-script");
        let share = root.join("prefix/share/seagent");
        fs::create_dir_all(share.join("vm")).unwrap();
        fs::create_dir_all(root.join("prefix/bin")).unwrap();
        fs::write(share.join(SHIPPED_SCRIPT), "#!/bin/sh\n").unwrap();
        fs::write(share.join("vm/seagent-vm-guest"), "elf").unwrap();
        let exe = root.join("prefix/bin/seagent");
        let got = build_script_in(None, None, Some(&exe), &[]);
        assert_eq!(got.canonicalize().unwrap(), share.join(SHIPPED_SCRIPT).canonicalize().unwrap());
        assert!(shipped_agent(&got).is_some(), "the shipped guest agent is passed as --agent");
        // An explicit SEAGENT_REPO_ROOT still wins; with nothing installed the error names the script.
        assert_eq!(build_script_in(Some(root.clone()), None, Some(&exe), &[]), root.join(BUILD_SCRIPT));
        assert_eq!(build_script_in(None, None, Some(&root.join("elsewhere/bin/seagent")), &[]), PathBuf::from(BUILD_SCRIPT));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn build_without_the_script_is_a_clear_error() {
        let data = tmp_dir("no-script");
        let repo = tmp_dir("empty-repo");
        let cfg = VmConfig::default();
        std::env::set_var("SEAGENT_REPO_ROOT", &repo);
        let res = GuestImage::build(&cfg, &data, false);
        std::env::remove_var("SEAGENT_REPO_ROOT");
        let err = res.expect_err("no builder script, no image (and never a download from a test)");
        assert!(err.contains("build script not found"), "clear, and tells the user what to do: {err}");
        assert!(err.contains(BUILD_SCRIPT), "names the script: {err}");
        let _ = fs::remove_dir_all(&data);
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn the_legacy_kernel_dir_is_still_found_and_verified() {
        let data = tmp_dir("legacy");
        let kernel_dir = data.join("vm").join("kernel");
        fs::create_dir_all(&kernel_dir).unwrap();
        write(&kernel_dir, KERNEL_FILE, b"legacy kernel");
        write(&kernel_dir, INITRAMFS_FILE, b"legacy initramfs");

        let cfg = VmConfig::default();
        let img = GuestImage::find(&cfg, &data).expect("legacy layout");
        assert_eq!(img.kernel(), kernel_dir.join(KERNEL_FILE));
        assert_eq!(img.initramfs(), kernel_dir.join(INITRAMFS_FILE));
        assert_eq!(img.manifest.source, "legacy kernel dir");
        img.verify().expect("digests were taken from the files");
        let _ = fs::remove_dir_all(&data);
    }

    #[test]
    fn the_builders_nested_manifest_shape_loads() {
        let dir = tmp_dir("nested");
        let kernel = write(&dir, KERNEL_FILE, b"kernel bytes");
        let initramfs = write(&dir, INITRAMFS_FILE, b"initramfs bytes");
        let json = format!(
            r#"{{
  "image_version": 1,
  "built_at": "2026-01-01T00:00:00Z",
  "kernel": {{"path": "vmlinux", "sha256": "{}", "size": {}, "source_url": "https://example.invalid/vmlinux"}},
  "initramfs": {{"path": "initramfs.cpio.gz", "sha256": "{}", "size": {}}},
  "agent": {{"sha256": "{}", "version": "seagent-vm-guest 0.1.0", "target": "x86_64-unknown-linux-musl", "init": "/sbin/init"}},
  "alpine": {{"version": "3.20.3", "url": "https://example.invalid/alpine.tar.gz", "sha256": "aa"}}
}}"#,
            sha256_file(&kernel).unwrap(),
            fs::metadata(&kernel).unwrap().len(),
            sha256_file(&initramfs).unwrap(),
            fs::metadata(&initramfs).unwrap().len(),
            "b".repeat(64)
        );
        write(&dir, MANIFEST_FILE, json.as_bytes());

        let img = GuestImage::load(&dir).expect("build-image.sh output shape");
        assert_eq!(img.manifest.alpine, "3.20.3");
        assert_eq!(img.manifest.agent_sha256, "b".repeat(64));
        assert_eq!(img.manifest.source, BUILD_SCRIPT);
        assert_eq!(img.manifest.built_at, "2026-01-01T00:00:00Z");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_boot_file_is_named() {
        let dir = tmp_dir("missing");
        let kernel = write(&dir, KERNEL_FILE, b"kernel");
        let initramfs = write(&dir, INITRAMFS_FILE, b"initramfs");
        write(&dir, MANIFEST_FILE, manifest_json(&kernel, &initramfs).as_bytes());
        fs::remove_file(&initramfs).unwrap();

        let err = GuestImage::load(&dir).expect_err("missing initramfs");
        assert!(err.contains(INITRAMFS_FILE), "names the file: {err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
