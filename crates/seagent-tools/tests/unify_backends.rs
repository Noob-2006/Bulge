//! B6 conformance: every backend behind `seagent_vm::unify::IsolatedEnv`.
//!
//! The suite is deliberately run against the *real* backends (not fakes): `local`,
//! `bwrap`, `landlock` on any machine, the microVM and the container engines behind
//! `#[ignore]`. What it checks is what the interface promises — an exit code, two
//! output streams that are really two, files that round-trip through the
//! environment, a timeout that is honoured, undo points that are either real or
//! honestly absent, and a `free()` that can be called twice.
//!
//! Nothing here reads `$HOME`/`SEAGENT_HOME`: every environment gets a throwaway data
//! dir under `$TMPDIR` and a workspace of its own, both removed on drop. The
//! `#[ignore]` tests start a VM / a container and are the only ones that need
//! anything beyond a bare machine:
//!
//! ```text
//! cargo test -p seagent-tools --test unify_backends -- --ignored --nocapture
//! ```

use seagent_tools::exec::unify::{caps_of, open};
use seagent_tools::exec::{BackendCtx, ExecConfig, BACKENDS};
use seagent_tools::exec::container::ContainerConfig;
use seagent_tools::exec::sandbox::SandboxConfig;
use seagent_vm::isolation::{isolation_of_backend, IsolationLevel};
use seagent_vm::trust::TrustTier;
use seagent_vm::unify::{EnvSpec, IsolatedEnv};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ───────────── scaffolding ─────────────

/// A directory under `$TMPDIR` that removes itself (and everything the backends
/// created inside it) when the test ends, including on a panic.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let d = base.join(format!("seagent-unify-{tag}-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("create {}: {e}", d.display()));
        TempDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The data dir and workspace for one environment. `home` stands in for
/// `~/.local/share/seagent`, so no backend can reach the operator's real state.
fn scratch(tag: &str, sandboxed: bool) -> (TempDir, BackendCtx) {
    let d = TempDir::new(tag);
    let ws = d.path().join("workspace");
    let home = d.path().join("home");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    // A container name is `seagent-<scope key>`: a test-owned, pid-scoped name, never
    // a label-wide pattern a cleanup would widen.
    let ctx = BackendCtx { workspace: ws, scope_key: format!("test-unify-{}", std::process::id()), secrets: Arc::new(|s: &str| s.to_string()), home, sandboxed };
    (d, ctx)
}

/// A sandbox config that lets a namespace sandbox see the real workspace.
fn sandbox_cfg() -> ExecConfig {
    ExecConfig { sandbox: SandboxConfig { mode: "all".into(), workspace_access: "rw".into(), ..Default::default() }, ..ExecConfig::default() }
}

/// Open `name` or report that this machine cannot (skip, not fail: the suite runs
/// on every developer machine and in CI without KVM, bwrap or an engine).
fn open_or_skip(name: &str, cfg: &ExecConfig, ctx: &BackendCtx) -> Option<Arc<dyn IsolatedEnv>> {
    match open(name, cfg, ctx) {
        Ok(e) => Some(e),
        Err(e) => {
            eprintln!("SKIP: backend `{name}` is not usable on this machine: {e}");
            None
        }
    }
}

// ───────────── the suite ─────────────

/// Everything the interface promises, checked against one environment.
fn conformance(env: &dyn IsolatedEnv, ws: &Path) {
    let caps = env.caps();
    let note = format!("{} ({})", caps.id, caps.level.label());
    assert!(!caps.id.is_empty(), "an environment needs an id");
    if caps.level != IsolationLevel::MicroVm {
        assert!(caps.warning.as_deref().is_some_and(|w| !w.is_empty()), "{note} must carry the warning its level owes: {caps:?}");
    }

    // 1. exit code, and stdout/stderr kept apart.
    let out = env
        .run(&EnvSpec::new(ws, TrustTier::Owner, "printf 'a'; printf 'b' >&2; exit 3", Duration::from_secs(60)).with_cwd(ws))
        .unwrap_or_else(|e| panic!("{note}: run: {e}"));
    assert_eq!(out.exit, Some(3), "{note}: the exit code must survive: {out:?}");
    assert!(!out.timed_out, "{note}: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stdout.trim_end(), "a", "{note}: stdout must be stdout only (no stderr, no wrapper noise): {stdout:?}");
    assert_eq!(stderr.trim_end(), "b", "{note}: stderr must be separate: {stderr:?}");

    // 2. files: round trip through the workspace, and never outside it.
    env.put_file("probe/round.txt", b"round-trip\n").unwrap_or_else(|e| panic!("{note}: put_file: {e}"));
    assert_eq!(env.get_file("probe/round.txt").unwrap(), Some(b"round-trip\n".to_vec()), "{note}: put/get round trip");
    assert_eq!(env.get_file("probe/absent.txt").unwrap(), None, "{note}: a missing file is None, not empty");
    assert!(env.put_file("../escape.txt", b"x").is_err(), "{note}: `..` must be refused");
    assert!(env.put_file("/etc/seagent-unify-test", b"x").is_err(), "{note}: an absolute path must be refused");
    assert!(!ws.parent().unwrap_or(ws).join("escape.txt").exists(), "{note}: nothing may be written outside the workspace");

    // 3. the working directory is honoured, and the file from (2) is visible there.
    let out = env
        .run(&EnvSpec::new(ws, TrustTier::Owner, "cat round.txt", Duration::from_secs(60)).with_cwd(ws.join("probe")))
        .unwrap_or_else(|e| panic!("{note}: run with cwd: {e}"));
    assert_eq!(out.exit, Some(0), "{note}: cwd run: {out:?}");
    assert_eq!(out.stdout, b"round-trip\n", "{note}: the command must run inside the workspace: {out:?}");

    // 4. the timeout is honoured (not merely reported).
    let started = Instant::now();
    let out = env
        .run(&EnvSpec::new(ws, TrustTier::Owner, "sleep 5; echo late", Duration::from_secs(1)).with_cwd(ws))
        .unwrap_or_else(|e| panic!("{note}: run (timeout): {e}"));
    assert!(out.timed_out, "{note}: `sleep 5` with a 1s timeout must report a timeout: {out:?}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("late"), "{note}: the killed command must not have finished: {out:?}");
    assert!(started.elapsed() < Duration::from_secs(4), "{note}: the timeout must cut the command short (took {:?})", started.elapsed());

    // 5. undo: real, or honestly absent — never a `Some` that `undo` cannot honour.
    env.put_file("probe/undo.txt", b"original\n").unwrap_or_else(|e| panic!("{note}: put_file: {e}"));
    let declared = env.caps().snapshots;
    match env.snapshot("conformance").unwrap_or_else(|e| panic!("{note}: snapshot: {e}")) {
        Some(name) => {
            assert!(declared, "{note}: caps said it cannot snapshot, yet snapshot() named one");
            assert!(!name.is_empty(), "{note}: an undo point needs a name");
            std::fs::remove_file(ws.join("probe/undo.txt")).unwrap_or_else(|e| panic!("{note}: remove the probe: {e}"));
            assert_eq!(env.get_file("probe/undo.txt").unwrap(), None, "{note}: the probe must be gone before undo");
            let restored = env.undo(None).unwrap_or_else(|e| panic!("{note}: undo: {e}"));
            assert!(restored.is_some(), "{note}: undo() must report the point it restored");
            assert_eq!(env.get_file("probe/undo.txt").unwrap(), Some(b"original\n".to_vec()), "{note}: undo must really restore the file");
        }
        None => {
            assert!(!declared, "{note}: caps promised undo points but snapshot() returned none");
            assert_eq!(env.undo(None).unwrap(), None, "{note}: with no undo point there is nothing to undo — no fake Some");
        }
    }

    // 6. teardown is idempotent.
    env.free();
    env.free();
}

// ───────────── tests that run on a bare machine ─────────────

#[test]
fn every_backend_name_has_an_environment_with_the_floor_it_claims() {
    let (_d, ctx) = scratch("caps", false);
    let cfg = ExecConfig::default();
    for name in BACKENDS {
        let caps = caps_of(name, &cfg, &ctx).unwrap_or_else(|e| panic!("caps_of({name}): {e}"));
        if *name == seagent_tools::exec::unify::AUTO {
            // `auto` answers with the backend the policy picked (`local` on a machine without
            // a guest image), and that name is in the same table.
            assert_eq!(caps.id, caps_of(&caps.id, &cfg, &ctx).unwrap().id, "`auto` resolves to a real name");
            continue;
        }
        assert_eq!(caps.id, *name);
        assert_eq!(caps.level, isolation_of_backend(name), "{name}: one table, one level");
        if caps.level == IsolationLevel::MicroVm {
            // Only a real microVM may stay silent — and only when this machine can
            // actually boot one (otherwise `caps_of` adds the blocker).
            continue;
        }
        let warning = caps.warning.as_deref().unwrap_or_else(|| panic!("{name}: a weaker level must warn: {caps:?}"));
        assert!(!warning.trim().is_empty(), "{name}: {caps:?}");
        assert!(warning.contains(name), "{name}: the warning must name the backend: {warning}");
    }
    // An unknown backend is an error, not a host-level environment by accident.
    let e = caps_of("no-such-backend", &cfg, &ctx).unwrap_err();
    assert!(e.contains("unknown exec backend"), "{e}");
    assert!(caps_of("", &cfg, &ctx).is_err());
    // `auto` answers from the same table, and warns when the answer is weaker.
    let auto = caps_of("auto", &cfg, &ctx).unwrap();
    assert_eq!(auto.level, isolation_of_backend(&auto.id), "{auto:?}");
    assert!(auto.level == IsolationLevel::MicroVm || auto.warning.is_some(), "{auto:?}");
    // Asking for a VM says whether this machine can boot one, without booting.
    let vm = caps_of("vm", &cfg, &ctx).unwrap();
    assert_eq!(vm.level, IsolationLevel::MicroVm);
    if !seagent_vm::policy::capabilities(&cfg.vm, &ctx.home).can_boot_vm() {
        assert!(vm.warning.as_deref().is_some_and(|w| w.contains("cannot boot a microVM")), "an unreachable claim is reported: {vm:?}");
    }
}

#[test]
fn local_passes_the_conformance_suite() {
    let (_d, ctx) = scratch("local", false);
    let env = open("local", &ExecConfig::default(), &ctx).expect("the host environment always opens");
    assert_eq!(env.caps().level, IsolationLevel::Host);
    assert!(!env.caps().workspace_copy, "local work sees the host's own files");
    conformance(env.as_ref(), &ctx.workspace);
}

#[test]
fn bwrap_passes_the_conformance_suite() {
    let (_d, ctx) = scratch("bwrap", true);
    let cfg = sandbox_cfg();
    let Some(env) = open_or_skip("bwrap", &cfg, &ctx) else { return };
    assert_eq!(env.caps().level, isolation_of_backend("bwrap"));
    conformance(env.as_ref(), &ctx.workspace);
}

#[test]
fn landlock_passes_the_conformance_suite() {
    let (_d, ctx) = scratch("landlock", true);
    let cfg = sandbox_cfg();
    let Some(env) = open_or_skip("landlock", &cfg, &ctx) else { return };
    assert_eq!(env.caps().level, isolation_of_backend("landlock"));
    conformance(env.as_ref(), &ctx.workspace);
}

#[test]
fn auto_opens_the_environment_it_describes() {
    let (_d, ctx) = scratch("auto", false);
    let cfg = ExecConfig::default();
    let claimed = caps_of("auto", &cfg, &ctx).unwrap();
    let env = open("auto", &cfg, &ctx).unwrap_or_else(|e| panic!("auto must open something usable: {e}"));
    let real = env.caps();
    assert_eq!(real.id, claimed.id, "open() must give the environment caps_of described: {real:?} vs {claimed:?}");
    if real.level != claimed.level {
        // A downgrade is allowed, but only out loud.
        assert!(real.warning.is_some(), "a level below the claim must be warned about: {real:?}");
    }
    assert_eq!(real.level, isolation_of_backend(&real.id), "{real:?}");
    let out = env.run(&EnvSpec::new(&ctx.workspace, TrustTier::Owner, "echo auto-ok", Duration::from_secs(60))).unwrap_or_else(|e| panic!("auto run: {e}"));
    assert!(out.success() && out.stdout.starts_with(b"auto-ok"), "{out:?}");
    env.free();
}

#[test]
fn nothing_falls_back_to_local_silently() {
    let (_d, ctx) = scratch("no-fallback", false);
    let cfg = ExecConfig::default();
    // A name nobody knows: an error, not the host.
    let e = match open("no-such-backend", &cfg, &ctx) {
        Ok(env) => panic!("an unknown name must not open: {}", env.caps().line()),
        Err(e) => e,
    };
    assert!(e.contains("no-such-backend"), "{e}");
    // Backends that need configuration say so (instead of quietly running here).
    for name in ["ssh", "modal", "daytona", "vercel"] {
        let e = open(name, &cfg, &ctx).err().unwrap_or_else(|| panic!("{name}: an unconfigured backend must not open"));
        assert!(!e.trim().is_empty(), "{name}: the error must name the reason");
    }
}

// ───────────── a real microVM ─────────────

/// A guest image, if this machine has one: `$SEAGENT_VM_IMAGE_DIR` first, then the
/// builder's default `$TMPDIR/seagent-vm-image`.
fn image_dir() -> Option<PathBuf> {
    let from_env = std::env::var_os("SEAGENT_VM_IMAGE_DIR").map(PathBuf::from);
    let default = std::env::var_os("TMPDIR").map(|t| PathBuf::from(t).join("seagent-vm-image"));
    from_env.into_iter().chain(default).find(|d| d.join("vmlinux").is_file() && d.join("initramfs.cpio.gz").is_file())
}

/// The Firecracker binary: `$FIRECRACKER`, then `PATH`, then a release tarball
/// unpacked under `$TMPDIR/fc` (what `packaging/vm/README.md` suggests).
fn firecracker() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("FIRECRACKER").map(PathBuf::from) {
        return p.is_file().then_some(p);
    }
    if let Some(p) = seagent_vm::isolation::which("firecracker") {
        return Some(p);
    }
    let base = std::env::var_os("TMPDIR").map(PathBuf::from)?;
    let unpacked: Vec<PathBuf> = std::fs::read_dir(base.join("fc")).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    for dir in unpacked {
        let entries: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
            Err(_) => continue,
        };
        for p in entries {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if name.starts_with("firecracker-v") && !name.ends_with(".debug") && p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn vm_config() -> Option<seagent_vm::VmConfig> {
    let img = image_dir()?;
    let fc = firecracker()?;
    Some(seagent_vm::VmConfig {
        provider: "firecracker".into(),
        kernel: img.join("vmlinux").display().to_string(),
        initramfs: img.join("initramfs.cpio.gz").display().to_string(),
        firecracker: fc.display().to_string(),
        memory_mb: 256,
        vcpu: 1,
        ..Default::default()
    })
}

/// Windows counterpart of `a_real_microvm_passes_the_conformance_suite`: the same suite against
/// the Windows substitute, QEMU + WHPX (TCG when the platform feature is off), from
/// `SEAGENT_VM_IMAGE_DIR` (a `--build-kernel` image: QEMU needs the PCI kernel).
#[cfg(windows)]
#[test]
#[ignore = "boots a real VM (needs QEMU for Windows and SEAGENT_VM_IMAGE_DIR)"]
fn a_real_qemu_whpx_vm_passes_the_conformance_suite() {
    let Some(img) = image_dir() else {
        eprintln!("SKIP: set SEAGENT_VM_IMAGE_DIR to a built image");
        return;
    };
    if seagent_vm::host::find_tool(seagent_vm::host::native_qemu()).is_none() {
        eprintln!("SKIP: qemu-system-x86_64 not found");
        return;
    }
    let vm = seagent_vm::VmConfig {
        provider: "qemu".into(),
        allow_fallback: false,
        kernel: img.join("vmlinux").display().to_string(),
        initramfs: img.join("initramfs.cpio.gz").display().to_string(),
        memory_mb: 512,
        vcpu: 2,
        ..Default::default()
    };
    let (_d, ctx) = scratch("winvm", false);
    let cfg = ExecConfig { vm, ..ExecConfig::default() };
    let env = open("vm", &cfg, &ctx).unwrap_or_else(|e| panic!("open(vm): {e}"));
    let caps = env.caps();
    assert_eq!((caps.level, caps.uid), (IsolationLevel::MicroVm, Some(1000)), "{caps:?}");
    assert!(caps.workspace_copy && caps.snapshots && caps.broker, "{caps:?}");
    eprintln!("ran the QEMU+WHPX conformance: {}", caps.line());
    conformance(env.as_ref(), &ctx.workspace);
}

#[test]
#[ignore = "boots a real microVM (needs /dev/kvm, firecracker and a guest image)"]
fn a_real_microvm_passes_the_conformance_suite() {
    if !Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: /dev/kvm is missing (no hardware virtualisation on this machine)");
        return;
    }
    let Some(vm) = vm_config() else {
        eprintln!("SKIP: no guest image; build one with packaging/vm/build-image.sh --out \"$TMPDIR/seagent-vm-image\" and put firecracker in $TMPDIR/fc or $FIRECRACKER");
        return;
    };
    let (_d, ctx) = scratch("vm", false);
    let cfg = ExecConfig { vm, ..ExecConfig::default() };
    let env = open("vm", &cfg, &ctx).unwrap_or_else(|e| panic!("open(vm): {e}"));
    let caps = env.caps();
    assert_eq!(caps.level, IsolationLevel::MicroVm, "the reference implementation must be a real microVM: {caps:?}");
    assert_eq!(caps.uid, Some(1000), "the guest runs the work as uid 1000: {caps:?}");
    assert!(caps.workspace_copy && caps.snapshots && caps.broker, "{caps:?}");
    assert!(caps.warning.is_none(), "a real microVM has nothing to qualify: {caps:?}");
    eprintln!("ran the microVM conformance: {}", caps.line());
    conformance(env.as_ref(), &ctx.workspace);

    // The undo point of the reference implementation, spelled out: a deleted file
    // comes back.
    env.put_file("undo/keep.txt", b"keep me\n").unwrap();
    let point = env.snapshot("microvm-conformance").unwrap_or_else(|e| panic!("snapshot: {e}")).expect("a microVM must be able to snapshot");
    assert!(env.run(&EnvSpec::new(&ctx.workspace, TrustTier::Owner, "cat undo/keep.txt", Duration::from_secs(60))).unwrap().success());
    std::fs::remove_file(ctx.workspace.join("undo/keep.txt")).expect("remove the probe");
    assert_eq!(env.get_file("undo/keep.txt").unwrap(), None);
    let restored = env.undo(Some(&point)).unwrap_or_else(|e| panic!("undo: {e}"));
    assert_eq!(restored.as_deref(), Some(point.as_str()), "undo must name the point it restored");
    assert_eq!(env.get_file("undo/keep.txt").unwrap(), Some(b"keep me\n".to_vec()), "undo must really restore the deleted file");
    env.free();
}

// ───────────── containers ─────────────

/// Remove the container this test created, whatever happened. Only the exact
/// name `seagent-test-unify-<pid>` is ever touched.
struct ContainerGuard {
    binary: String,
    name: String,
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.binary).args(["rm", "-f", &self.name]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    }
}

/// A container engine that is installed, rootless-usable and already has an image
/// with `bash` in it (the client commands run `bash -c`). No pull: the test must
/// work offline.
fn container_engine(binary: &str) -> Option<(String, String)> {
    let ok = std::process::Command::new(binary).arg("version").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        return None;
    }
    for image in ["ubuntu:22.04", "debian:bookworm-slim", "docker.io/library/ubuntu:22.04"] {
        let present = std::process::Command::new(binary).args(["image", "exists", image]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
        if present {
            return Some((binary.to_string(), image.to_string()));
        }
    }
    None
}

fn container_conformance(binary: &str, tag: &str) {
    let Some((bin, image)) = container_engine(binary) else {
        eprintln!("SKIP: `{binary}` is not installed or has none of ubuntu:22.04 / debian:bookworm-slim locally (offline: no pull)");
        return;
    };
    let (_d, ctx) = scratch(tag, true);
    let name = format!("seagent-test-unify-{}", std::process::id());
    let _guard = ContainerGuard { binary: bin.clone(), name: name.clone() };
    // The engine's own defaults (caps dropped, network none, read-only rootfs),
    // with a locally present image so nothing is pulled.
    let (docker, podman) = if bin.contains("podman") {
        (ContainerConfig::docker(), ContainerConfig { image, ..ContainerConfig::podman() })
    } else {
        (ContainerConfig { image, ..ContainerConfig::docker() }, ContainerConfig::podman())
    };
    let cfg = ExecConfig { docker, podman, ..sandbox_cfg() };
    let Some(env) = open_or_skip(tag, &cfg, &ctx) else { return };
    assert_eq!(env.caps().level, isolation_of_backend(tag), "{}", env.caps().line());
    eprintln!("ran the {tag} conformance: {}", env.caps().line());
    conformance(env.as_ref(), &ctx.workspace);
    env.free();
    // The container this environment created is gone; its name was ours alone.
    let listed = std::process::Command::new(&bin).args(["ps", "-a", "--format", "{{.Names}}"]).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    assert!(!listed.lines().any(|l| l.trim() == name), "free() must remove the container it created: {listed}");
}

#[test]
#[ignore = "creates a real podman container (needs podman and a local image)"]
fn a_podman_container_passes_the_conformance_suite() {
    container_conformance("podman", "podman");
}

#[test]
#[ignore = "creates a real docker container (needs docker and a local image)"]
fn a_docker_container_passes_the_conformance_suite() {
    container_conformance("docker", "docker");
}
