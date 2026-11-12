//! The VM that ships *inside* the installers: a pinned guest image plus the hypervisor
//! front-end the host OS needs, staged by `packaging/vm/bundle.sh` into the app's resources
//! (`<resources>/vm/`). With it a fresh install boots its tools in a microVM with nothing else
//! installed — no QEMU, VirtualBox or `seagent sandbox vm image build` on the user's side.
//!
//! ```text
//! vm/bundle.json                 what is here (written by bundle.sh, see `BundleInfo`)
//! vm/image/<arch>/manifest.json  the guest image (`crate::image`), kernel + initramfs
//! vm/runtime/qemu/…              Windows: QEMU (WHPX, TCG fallback) and its DLLs / firmware
//! vm/runtime/vfkit               macOS: vfkit (Virtualization.framework)
//! vm/runtime/firecracker         Linux: the static Firecracker release binary
//! vm/LICENSES/…                  licence texts and the source offer of each bundled binary
//! ```
//!
//! Where it is found: `$SEAGENT_VM_BUNDLE` (the desktop app sets it to its resource dir when it
//! starts the agent), else next to the running binary the way each installer lays it out
//! (Windows `<install dir>\vm`, macOS `Contents/Resources/vm`, Linux `/usr/lib/SE Agent/vm` and
//! the AppImage's `usr/lib/SE Agent/vm`). A user-built image (`<data>/vm/image`) and explicitly
//! configured tool paths still win; the bundle replaces only what is missing or left at its
//! default name.
//!
//! The image a build ships is pinned: `bundle.sh` prints the manifest's sha256 and the release
//! pipeline compiles it into the agent (`SEAGENT_VM_IMAGE_MANIFEST_SHA256`), so an installed
//! agent refuses a bundled image other than the one it was built and tested with. The manifest
//! in turn pins every file of the image (`GuestImage::verify`).

use crate::config::VmConfig;
use crate::image::{sha256_file, GuestImage, MANIFEST_FILE};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Explicit bundle directory (the desktop app sets it; tests and packagers use it too).
pub const ENV: &str = "SEAGENT_VM_BUNDLE";
/// The bundle's own description, next to `image/` and `runtime/`.
pub const BUNDLE_FILE: &str = "bundle.json";
/// Layout version of `bundle.json` this crate reads.
pub const BUNDLE_VERSION: u32 = 1;
/// sha256 of the bundled image's `manifest.json` this build was released with (`None` in
/// development builds, which accept any bundled image whose own manifest verifies).
pub const PINNED_MANIFEST_SHA256: Option<&str> = option_env!("SEAGENT_VM_IMAGE_MANIFEST_SHA256");

/// What the user is told to do when the bundled VM needs attention: a button in the app, never
/// a terminal command.
pub const REPAIR_HINT: &str = "open the SE Agent app → Settings → Virtual machine and click “Set up / repair VM” (or reinstall the app)";

/// `bundle.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BundleInfo {
    pub bundle_version: u32,
    /// `windows` / `macos` / `linux`: the host OS this bundle was staged for.
    pub os: String,
    /// Guest (= host) architecture, `x86_64` / `aarch64`.
    pub arch: String,
    pub image: ImageRef,
    pub runtime: RuntimeInfo,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageRef {
    /// Directory of the image, relative to the bundle (`image/x86_64`).
    pub dir: String,
    /// sha256 of its `manifest.json` (what the release pins).
    pub manifest_sha256: String,
}

/// The bundled hypervisor front-end.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeInfo {
    /// `qemu` / `vfkit` / `firecracker`.
    pub kind: String,
    /// Directory relative to the bundle (`runtime/qemu`).
    pub dir: String,
    /// The executable inside `dir` (`qemu-system-x86_64.exe`).
    pub exe: String,
    pub version: String,
    /// SPDX licence of the binary (`GPL-2.0-only` for QEMU).
    pub license: String,
    /// Where the binary came from, and the hash it was checked against before it was bundled.
    pub source: String,
    pub source_sha: String,
    /// Corresponding source code (the GPL source offer).
    pub source_code: String,
    /// Every bundled file (relative to `dir`) and its sha256, re-checked by "repair".
    pub files: BTreeMap<String, String>,
}

/// A located bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub dir: PathBuf,
    pub info: BundleInfo,
}

/// The bundle of this installation, if any.
pub fn locate() -> Option<Bundle> {
    locate_with(std::env::var_os(ENV).map(PathBuf::from), std::env::current_exe().ok().as_deref())
}

/// [`locate`] as a pure function of `$SEAGENT_VM_BUNDLE` and the running executable.
pub fn locate_with(env: Option<PathBuf>, exe: Option<&Path>) -> Option<Bundle> {
    let explicit = env.filter(|p| !p.as_os_str().is_empty());
    let cands: Vec<PathBuf> = match explicit {
        // An explicit directory is the only candidate: a test or a packager that names one
        // must never pick up another installation's bundle by accident.
        Some(p) => vec![p],
        None => candidates(exe),
    };
    cands.into_iter().find_map(|d| Bundle::open(&d).ok())
}

/// Where each installer puts the bundle, relative to the agent binary.
pub fn candidates(exe: Option<&Path>) -> Vec<PathBuf> {
    let Some(bin) = exe.and_then(Path::parent) else { return vec![] };
    // Parent directories are taken lexically (`Contents/MacOS/..` only resolves when MacOS exists).
    let up = bin.parent().unwrap_or(bin);
    vec![
        // Windows (NSIS / MSI): the agent sits in the install dir, resources next to it.
        bin.join("vm"),
        // macOS: Contents/MacOS/seagent → Contents/Resources/vm.
        up.join("Resources").join("vm"),
        // Linux deb / rpm (/usr/bin → /usr/lib/<product>) and the AppImage (usr/bin → usr/lib).
        up.join("lib").join("SE Agent").join("vm"),
        up.join("lib").join("seagent-desktop").join("vm"),
        // Release tarballs / install.sh: <prefix>/share/seagent/vm.
        up.join("share").join("seagent").join("vm"),
    ]
}

impl Bundle {
    /// Read `<dir>/bundle.json`.
    pub fn open(dir: &Path) -> Result<Bundle, String> {
        let p = dir.join(BUNDLE_FILE);
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let info: BundleInfo = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        if info.bundle_version != BUNDLE_VERSION {
            return Err(format!("{}: bundle_version {} (this agent reads {BUNDLE_VERSION})", p.display(), info.bundle_version));
        }
        for rel in [&info.image.dir, &info.runtime.dir, &info.runtime.exe] {
            if !plain_relative(rel) {
                return Err(format!("{}: `{rel}` must be a relative path inside the bundle", p.display()));
            }
        }
        Ok(Bundle { dir: dir.to_path_buf(), info })
    }

    pub fn image_dir(&self) -> PathBuf {
        self.dir.join(&self.info.image.dir)
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.dir.join(&self.info.runtime.dir)
    }

    /// The bundled runtime executable, when it is on disk.
    pub fn runtime_exe(&self) -> Option<PathBuf> {
        (!self.info.runtime.exe.is_empty()).then(|| self.runtime_dir().join(&self.info.runtime.exe)).filter(|p| p.is_file())
    }

    /// The bundled kernel + initramfs paths without hashing them (provider selection runs often;
    /// the boot itself verifies, see [`Bundle::image`]).
    pub fn image_paths(&self) -> Option<(PathBuf, PathBuf)> {
        let dir = self.image_dir();
        let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join(MANIFEST_FILE)).ok()?).ok()?;
        if m["image_version"].as_u64() != Some(u64::from(crate::IMAGE_VERSION)) {
            return None;
        }
        let k = dir.join(m["kernel"]["path"].as_str().filter(|p| plain_relative(p))?);
        let i = dir.join(m["initramfs"]["path"].as_str().filter(|p| plain_relative(p))?);
        (k.is_file() && i.is_file()).then_some((k, i))
    }

    /// The bundled image, fully verified: every file against its manifest, the manifest against
    /// `bundle.json` and against the hash this build pins.
    pub fn image(&self) -> Result<GuestImage, String> {
        let dir = self.image_dir();
        let got = sha256_file(&dir.join(MANIFEST_FILE)).map_err(|e| format!("the bundled guest image is missing ({e}) — {REPAIR_HINT}"))?;
        check_pin(&got, &self.info.image.manifest_sha256, PINNED_MANIFEST_SHA256)?;
        GuestImage::load(&dir).map_err(|e| format!("the bundled guest image does not verify ({}) — {REPAIR_HINT}", e.split("; run `").next().unwrap_or(&e)))
    }

    /// Re-hash every bundled runtime file against `bundle.json` (the "repair" check).
    pub fn verify_runtime(&self) -> Result<usize, String> {
        let dir = self.runtime_dir();
        if self.info.runtime.files.is_empty() {
            return Err(format!("{}: the bundle lists no runtime files", self.dir.join(BUNDLE_FILE).display()));
        }
        for (rel, want) in &self.info.runtime.files {
            if !plain_relative(rel) {
                return Err(format!("bundle.json: runtime file `{rel}` is not a relative path"));
            }
            let got = sha256_file(&dir.join(rel)).map_err(|e| format!("bundled {} file missing: {e}", self.info.runtime.kind))?;
            if !got.eq_ignore_ascii_case(want) {
                return Err(format!("bundled {} file `{rel}` is damaged (sha256 {got}, expected {want})", self.info.runtime.kind));
            }
        }
        Ok(self.info.runtime.files.len())
    }
}

/// The image's manifest hash must match what `bundle.json` recorded and, in a release build,
/// what the build pins. An empty recorded value is a hand-assembled development bundle.
pub fn check_pin(got: &str, recorded: &str, pinned: Option<&str>) -> Result<(), String> {
    if !recorded.is_empty() && !recorded.eq_ignore_ascii_case(got) {
        return Err(format!("the bundled guest image was changed after it was packaged (manifest sha256 {got}, bundle.json says {recorded}) — {REPAIR_HINT}"));
    }
    if let Some(pin) = pinned.filter(|p| !p.is_empty()) {
        if !pin.eq_ignore_ascii_case(got) {
            return Err(format!("the bundled guest image is not the one this SE Agent build was released with (manifest sha256 {got}, pinned {pin}) — {REPAIR_HINT}"));
        }
    }
    Ok(())
}

/// `cfg` with the bundled hypervisor front-end filled in where the user left the default
/// name: Windows QEMU, macOS vfkit, Linux Firecracker. An explicitly configured path is kept.
pub fn apply(cfg: &VmConfig) -> VmConfig {
    apply_with(cfg, locate().as_ref())
}

/// [`apply`] for a given bundle (tests).
pub fn apply_with(cfg: &VmConfig, bundle: Option<&Bundle>) -> VmConfig {
    let mut out = cfg.clone();
    let Some(b) = bundle else { return out };
    let Some(exe) = b.runtime_exe() else { return out };
    let exe = exe.display().to_string();
    let defaults = VmConfig::default();
    match b.info.runtime.kind.as_str() {
        "qemu" if cfg.qemu == defaults.qemu => out.qemu = exe,
        "vfkit" if cfg.vfkit == defaults.vfkit => out.vfkit = exe,
        "firecracker" if cfg.firecracker == defaults.firecracker => out.firecracker = exe,
        _ => {}
    }
    out
}

/// What the user must do to get a microVM back, phrased for how this agent was installed: the
/// app's button when it carries a bundle, the builder otherwise (a source checkout / server).
pub fn fix_hint() -> String {
    if locate().is_some() {
        REPAIR_HINT.to_string()
    } else {
        "build the guest image (`seagent sandbox vm image build`)".to_string()
    }
}

fn plain_relative(p: &str) -> bool {
    !p.is_empty() && !Path::new(p).is_absolute() && !p.contains('\\') && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> seagent_core::tmp::TempDir {
        seagent_core::tmp::TempDir::new(&format!("seagent-vm-bundle-{tag}"))
    }

    /// A complete little bundle: a fake image that verifies and a fake runtime executable.
    pub(crate) fn fake_bundle(root: &Path, kind: &str, exe: &str) -> Bundle {
        let img = root.join("image/x86_64");
        std::fs::create_dir_all(&img).unwrap();
        std::fs::write(img.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(img.join("initramfs.cpio.gz"), b"initramfs").unwrap();
        let entry = |n: &str| serde_json::json!({"path": n, "sha256": sha256_file(&img.join(n)).unwrap(), "size": std::fs::metadata(img.join(n)).unwrap().len()});
        std::fs::write(img.join(MANIFEST_FILE), serde_json::json!({"image_version": 1, "kernel": entry("vmlinux"), "initramfs": entry("initramfs.cpio.gz")}).to_string()).unwrap();
        let rt = root.join("runtime").join(kind);
        std::fs::create_dir_all(&rt).unwrap();
        std::fs::write(rt.join(exe), b"binary").unwrap();
        let info = BundleInfo {
            bundle_version: 1,
            os: std::env::consts::OS.into(),
            arch: "x86_64".into(),
            image: ImageRef { dir: "image/x86_64".into(), manifest_sha256: sha256_file(&img.join(MANIFEST_FILE)).unwrap() },
            runtime: RuntimeInfo { kind: kind.into(), dir: format!("runtime/{kind}"), exe: exe.into(), files: [(exe.to_string(), sha256_file(&rt.join(exe)).unwrap())].into(), ..Default::default() },
        };
        std::fs::write(root.join(BUNDLE_FILE), serde_json::to_string(&info).unwrap()).unwrap();
        Bundle::open(root).unwrap()
    }

    #[test]
    fn a_bundle_next_to_the_binary_is_found_per_installer_layout() {
        let t = tmp("layout");
        // Windows: <install dir>\seagent.exe + <install dir>\vm
        fake_bundle(&t.path().join("win/vm"), "qemu", "qemu-system-x86_64.exe");
        assert!(locate_with(None, Some(&t.path().join("win/seagent.exe"))).is_some());
        // macOS: Contents/MacOS/seagent + Contents/Resources/vm
        fake_bundle(&t.path().join("SE Agent.app/Contents/Resources/vm"), "vfkit", "vfkit");
        let b = locate_with(None, Some(&t.path().join("SE Agent.app/Contents/MacOS/seagent"))).expect("macOS layout");
        assert_eq!(b.info.runtime.kind, "vfkit");
        // Linux deb/rpm/AppImage: usr/bin/seagent + usr/lib/SE Agent/vm
        fake_bundle(&t.path().join("usr/lib/SE Agent/vm"), "firecracker", "firecracker");
        assert_eq!(locate_with(None, Some(&t.path().join("usr/bin/seagent"))).unwrap().info.runtime.kind, "firecracker");
        // An explicit $SEAGENT_VM_BUNDLE is the only candidate, even when it is empty.
        assert!(locate_with(Some(t.path().join("nowhere")), Some(&t.path().join("win/seagent.exe"))).is_none());
        assert!(locate_with(None, Some(&t.path().join("elsewhere/seagent"))).is_none());
    }

    #[test]
    fn the_bundled_image_verifies_and_a_changed_one_is_refused() {
        let t = tmp("verify");
        let b = fake_bundle(t.path(), "qemu", "qemu-system-x86_64.exe");
        let img = b.image().expect("verifies");
        assert_eq!(img.kernel(), t.path().join("image/x86_64/vmlinux"));
        assert_eq!(b.image_paths(), Some((t.path().join("image/x86_64/vmlinux"), t.path().join("image/x86_64/initramfs.cpio.gz"))));
        assert_eq!(b.verify_runtime(), Ok(1));
        // A damaged kernel: the manifest catches it, and the message is a button, not a command.
        std::fs::write(t.path().join("image/x86_64/vmlinux"), b"KERNEL").unwrap();
        let e = b.image().unwrap_err();
        assert!(e.contains("does not verify") && e.contains("Set up / repair VM") && !e.contains("seagent sandbox"), "{e}");
        // A damaged runtime file.
        std::fs::write(t.path().join("runtime/qemu/qemu-system-x86_64.exe"), b"other").unwrap();
        assert!(b.verify_runtime().unwrap_err().contains("damaged"));
    }

    #[test]
    fn the_pin_must_match_the_recorded_and_the_compiled_hash() {
        assert!(check_pin("ab", "", None).is_ok(), "a development bundle without a pin");
        assert!(check_pin("ab", "AB", Some("ab")).is_ok());
        assert!(check_pin("ab", "cd", None).unwrap_err().contains("changed after it was packaged"));
        assert!(check_pin("ab", "ab", Some("cd")).unwrap_err().contains("not the one this SE Agent build"));
    }

    #[test]
    fn the_bundled_runtime_replaces_only_default_tool_names() {
        let t = tmp("apply");
        let b = fake_bundle(t.path(), "qemu", "qemu-system-x86_64.exe");
        let cfg = apply_with(&VmConfig::default(), Some(&b));
        assert_eq!(PathBuf::from(&cfg.qemu), t.path().join("runtime/qemu/qemu-system-x86_64.exe"));
        assert_eq!(cfg.firecracker, VmConfig::default().firecracker, "other tools untouched");
        let mine = VmConfig { qemu: "/opt/my/qemu".into(), ..Default::default() };
        assert_eq!(apply_with(&mine, Some(&b)).qemu, "/opt/my/qemu", "a configured path wins");
        let f = tmp("apply-fc");
        let fc = fake_bundle(f.path(), "firecracker", "firecracker");
        assert_eq!(PathBuf::from(apply_with(&VmConfig::default(), Some(&fc)).firecracker), f.path().join("runtime/firecracker/firecracker"));
        assert_eq!(apply_with(&VmConfig::default(), None).qemu, VmConfig::default().qemu);
    }

    #[test]
    fn bundle_json_with_escaping_paths_is_rejected() {
        let t = tmp("escape");
        fake_bundle(t.path(), "qemu", "qemu-system-x86_64.exe");
        let mut info: BundleInfo = serde_json::from_str(&std::fs::read_to_string(t.path().join(BUNDLE_FILE)).unwrap()).unwrap();
        info.image.dir = "../../etc".into();
        std::fs::write(t.path().join(BUNDLE_FILE), serde_json::to_string(&info).unwrap()).unwrap();
        assert!(Bundle::open(t.path()).unwrap_err().contains("relative path inside the bundle"));
    }
}
