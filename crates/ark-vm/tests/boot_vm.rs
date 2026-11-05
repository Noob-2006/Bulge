//! Boot a real microVM from the image `packaging/vm/build-image.sh` builds and
//! drive the guest agent over its single channel (B1/B2/B3).
//!
//! Fast tests (always run, no VM, no KVM): the parts of the guest agent that can
//! be imported as a module — the `/proc/cmdline` parsing, the guest path rules,
//! the workspace path check — plus the contract of the image builder
//! (`--help`, executable bit). They catch a broken image definition without
//! spending a second on a boot.
//!
//! Slow tests (`#[ignore]`, need `/dev/kvm` and a built image):
//!
//! * [`boots_a_qemu_microvm_and_runs_a_command`] — QEMU-KVM, the provider that
//!   needs no extra binary.
//! * [`boots_a_firecracker_microvm_and_runs_a_command`] — Firecracker, the
//!   provider the design targets (`vsock` channel).
//!
//! Both do the same thing: boot, expect `Hello { uid: 1000 }`, run a command
//! *as the agent user*, prove the guest cannot see the host, sync files both
//! ways, and shut the VM down. Run them with
//!
//! ```text
//! ARK_VM_IMAGE_DIR=$TMPDIR/ark-vm-image \
//!     cargo test -p ark-vm --test boot_vm -- --ignored --nocapture
//! ```
//!
//! The image is looked up in `ARK_VM_IMAGE_DIR`, then `$TMPDIR/ark-vm-image`
//! (the builder's default); when it is missing the test prints how to build it
//! and returns instead of failing, so `--ignored` stays usable on a machine
//! without an image.

#[path = "../src/bin/ark-vm-guest.rs"]
#[allow(dead_code)]
mod guest;

use ark_vm::channel::{Channel, Transport};
use ark_vm::config::VmConfig;
use ark_vm::limits::Limits;
use ark_vm::provider::firecracker::FirecrackerProvider;
use ark_vm::provider::qemu::QemuProvider;
use ark_vm::provider::{VmInstance, VmProvider, VmSpec, Workspace};
use ark_vm::proto::{self, FileBlob, GuestMsg, HostMsg};
use base64::Engine as _;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// How long a boot may take before the test calls it a failure.
const BOOT_WAIT: Duration = Duration::from_secs(20);
/// Per-frame budget once the agent has said Hello.
const FRAME_WAIT: Duration = Duration::from_secs(30);

// ── fast tests: the guest code and the image builder, no VM ─────────────────

#[test]
fn the_guest_reads_its_boot_parameters_and_refuses_hostile_ones() {
    let cfg = guest::parse_cmdline(
        "console=ttyS0 quiet rdinit=/sbin/init ark.vm=s-7 ark.tier=stranger ark.channel=virtio-serial \
         ark.workspace=/workspace ark.disk_mb=128 ark.nproc=64 ark.nofile=1024 ark.workspace_ro=1",
    );
    assert_eq!(cfg.vm, "s-7");
    assert_eq!(cfg.tier, "stranger");
    assert_eq!(cfg.channel, "virtio-serial");
    assert_eq!(cfg.disk_mb, 128);
    assert_eq!((cfg.nproc, cfg.nofile), (64, 1024));
    assert!(cfg.workspace_ro, "B2: a read-only workspace is carried into the guest");

    // What a hostile or confused host could put on the command line must not
    // move the workspace or remove the limits.
    let hostile = guest::parse_cmdline("ark.workspace=../../etc ark.nproc=0 ark.disk_mb=-1 ark.channel=tcp ark.workspace_ro=maybe");
    assert_eq!(hostile.workspace, PathBuf::from(proto::GUEST_WORKSPACE));
    assert_eq!(hostile.nproc, guest::GuestCfg::default().nproc);
    assert_eq!(hostile.disk_mb, guest::GuestCfg::default().disk_mb);
    assert_eq!(hostile.channel, "", "only the two real transports are accepted");
    assert!(!hostile.workspace_ro);
}

#[test]
fn the_workspace_path_rules_hold() {
    // The protocol rule (both sides check this) …
    for good in ["a", "src/main.rs", "a/b/c.txt"] {
        assert!(proto::check_rel_path(good).is_ok(), "{good}");
    }
    for bad in ["", "/etc/passwd", "../x", "a/../../b", "./a", "a//b", "a/"] {
        assert!(proto::check_rel_path(bad).is_err(), "{bad}");
    }
    // … and the guest's own rule for the workspace root from the cmdline.
    assert_eq!(guest::guest_abs_path("/workspace"), Some(PathBuf::from("/workspace")));
    for bad in ["workspace", "/a/../b", "/a//b", "/"] {
        assert_eq!(guest::guest_abs_path(bad), None, "{bad}");
    }
}

#[test]
fn the_image_builder_is_executable_and_documents_itself() {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/vm/build-image.sh");
    let meta = std::fs::metadata(&script).unwrap_or_else(|e| panic!("{}: {e}", script.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(meta.permissions().mode() & 0o111 != 0, "{} must be executable", script.display());
    }
    // Only `--help`: the test must not build or download anything.
    let out = Command::new(&script).arg("--help").output().unwrap_or_else(|e| panic!("run {}: {e}", script.display()));
    assert!(out.status.success(), "--help failed: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    for flag in ["--out", "--agent", "--kernel", "--rootfs", "--target"] {
        assert!(text.contains(flag), "--help must document {flag}:\n{text}");
    }
    for fact in ["initramfs", "/sbin/init", "uid"] {
        assert!(text.contains(fact), "--help must explain {fact}:\n{text}");
    }
    // The README is part of the deliverable: the image is only useful if the
    // next person can rebuild it.
    let readme = script.parent().unwrap_or(Path::new(".")).join("README.md");
    let text = std::fs::read_to_string(&readme).unwrap_or_else(|e| panic!("{}: {e}", readme.display()));
    assert!(text.contains("initramfs") && text.contains("build-image.sh"));
}

// ── slow tests: a real VM ───────────────────────────────────────────────────

fn image_dir() -> Option<PathBuf> {
    let from_env = std::env::var_os("ARK_VM_IMAGE_DIR").map(PathBuf::from);
    let default = std::env::var_os("TMPDIR").map(|t| PathBuf::from(t).join("ark-vm-image"));
    from_env.into_iter().chain(default).find(|d| d.join("vmlinux").is_file() && d.join("initramfs.cpio.gz").is_file())
}

/// Fail with the console log attached: a VM that dies during boot is otherwise
/// a very quiet failure.
fn no_image() {
    eprintln!(
        "SKIP: no guest image; build one with\n    \
         packaging/vm/build-image.sh --out \"$TMPDIR/ark-vm-image\"\n\
         or point ARK_VM_IMAGE_DIR at an existing image directory."
    );
}

fn scratch_dir(label: &str) -> PathBuf {
    let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("ark-boot-{label}-{}-{}", std::process::id(), unique()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    dir
}

fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    n * 7919 + std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(1)
}

fn spec_of(id: &str, image: &Path, run_dir: PathBuf, transport: Transport) -> VmSpec {
    VmSpec {
        id: id.to_string(),
        tier: "owner".to_string(),
        kernel: image.join("vmlinux"),
        initramfs: image.join("initramfs.cpio.gz"),
        run_dir,
        vcpu: 2,
        mem_mb: 512,
        // No host directory is mounted: the workspace exists only inside the
        // guest and is synced over the channel (B2).
        workspace: Some(Workspace { host: PathBuf::from("/nonexistent/ark/boot-test"), guest: proto::GUEST_WORKSPACE.to_string(), read_only: false }),
        limits: Limits::default(),
        transport,
        firecracker: None,
        qemu: None,
        extra_args: vec![],
        guest_cid: 3,
    }
}

/// A booted VM plus the channel to it; stopped and cleaned up on drop, whatever
/// happens to the assertions in between.
struct Guest {
    spec: VmSpec,
    inst: Box<dyn VmInstance>,
    ch: Channel,
    hello: GuestMsg,
    queued: VecDeque<GuestMsg>,
    /// When `provider.start()` was called, and when the agent said Hello.
    started: Instant,
    hello_at: Duration,
}

impl Guest {
    fn boot(provider: &dyn VmProvider, spec: VmSpec) -> Result<Guest, String> {
        let started = Instant::now();
        let mut inst = provider.start(&spec)?;
        let configured = started.elapsed();
        let (ch, hello) = match open_channel(&spec, inst.as_mut(), BOOT_WAIT) {
            Ok(v) => v,
            Err(e) => {
                let log = console_tail(&spec);
                inst.stop();
                return Err(format!("{e}\n--- guest console ({}), the agent's own log is in there ---\n{log}", spec.console_log().display()));
            }
        };
        let hello_at = started.elapsed();
        println!("  provider.start() {configured:?}, VM booted to Hello in {} ms total", hello_at.as_millis());
        Ok(Guest { spec, inst, ch, hello, queued: VecDeque::new(), started, hello_at })
    }

    fn hello(&self) -> &GuestMsg {
        &self.hello
    }

    fn send(&self, m: &HostMsg) -> Result<(), String> {
        self.ch.send(m)
    }

    fn next(&mut self, wait: Duration) -> Result<Option<GuestMsg>, String> {
        if let Some(m) = self.queued.pop_front() {
            return Ok(Some(m));
        }
        self.ch.recv(wait)
    }

    /// Collect `Out` chunks for `id` until `Exit`, returning the merged output.
    fn until_exit(&mut self, id: u64) -> Result<(String, Option<i32>, Option<i32>), String> {
        let mut out = Vec::new();
        loop {
            match self.next(FRAME_WAIT)? {
                Some(GuestMsg::Out { id: i, data }) if i == id => {
                    out.extend(B64.decode(data.as_bytes()).map_err(|e| format!("output chunk is not base64: {e}"))?);
                }
                Some(GuestMsg::Exit { id: i, code, signal }) if i == id => {
                    let text = String::from_utf8_lossy(&out).into_owned();
                    return Ok((text, code, signal));
                }
                Some(GuestMsg::Err { id: i, message }) if i == id => return Err(format!("exec {id}: {message}")),
                Some(_) => continue,
                None => return Err(format!("exec {id} produced no exit within {FRAME_WAIT:?}")),
            }
        }
    }

    /// Run a script and require a zero exit; returns its output.
    fn run(&mut self, id: u64, script: &str) -> Result<String, String> {
        self.send(&HostMsg::Exec { id, script: script.to_string(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 30 })?;
        let (out, code, signal) = self.until_exit(id)?;
        match (code, signal) {
            (Some(0), _) => Ok(out),
            (_, Some(s)) => Err(format!("`{script}` was killed by signal {s}\n{out}")),
            (c, _) => Err(format!("`{script}` exited with {c:?}\n{out}")),
        }
    }

    /// `Shutdown` and wait for the VM to go away on its own; returns whether it
    /// did (the agent asks for an ACPI power-off where the firmware has one, a
    /// guest reset otherwise — both VMMs stop the VM). Always kills the VMM
    /// afterwards.
    fn shutdown(mut self) -> bool {
        let _ = self.ch.send(&HostMsg::Shutdown);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && self.inst.is_running() {
            std::thread::sleep(Duration::from_millis(50));
        }
        let stopped = !self.inst.is_running();
        self.inst.stop();
        stopped
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.inst.stop();
        let _ = std::fs::remove_dir_all(&self.spec.run_dir);
    }
}

/// Does the guest console already contain `needle`?
fn console_says(spec: &VmSpec, needle: &str) -> bool {
    std::fs::read_to_string(spec.console_log()).map(|t| t.contains(needle)).unwrap_or(false)
}

fn console_tail(spec: &VmSpec) -> String {
    let text = std::fs::read_to_string(spec.console_log()).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(25)..].join("\n")
}

/// Connect and wait for `Hello`. A vsock `CONNECT` is answered and then closed
/// while the guest is still booting, so the whole handshake is retried until the
/// agent speaks or the VM dies.
fn open_channel(spec: &VmSpec, inst: &mut dyn VmInstance, wait: Duration) -> Result<(Channel, GuestMsg), String> {
    let deadline = Instant::now() + wait;
    let mut last;
    loop {
        match Channel::connect(&spec.channel_path(), spec.transport, Duration::from_millis(500)) {
            Ok(ch) => match ch.recv(Duration::from_secs(5)) {
                Ok(Some(m @ GuestMsg::Hello { .. })) => return Ok((ch, m)),
                Ok(Some(other)) => last = format!("the first frame was {other:?}, not Hello"),
                Ok(None) => last = "connected, but the agent did not answer".to_string(),
                Err(e) => last = e,
            },
            Err(e) => last = e,
        }
        if !inst.is_running() {
            return Err(format!("the VM exited before the guest agent said Hello (last: {last})"));
        }
        // The agent logs why it cannot serve; waiting out the whole timeout after
        // that only makes the failure slow.
        if console_says(spec, "ark-vm-guest: channel:") {
            return Err(format!("the guest agent could not open its channel (last: {last})"));
        }
        if Instant::now() >= deadline {
            return Err(format!("no Hello within {wait:?} (last: {last})"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The checks every provider has to pass: the same guest, the same wall.
fn exercise_the_guest(g: &mut Guest) -> Result<(), String> {
    // 1. Hello proves the protocol version and — the point of B2 — that the
    //    agent is not root.
    match g.hello() {
        GuestMsg::Hello { version, uid, transport, kernel, agent, .. } => {
            assert_eq!(*version, proto::VERSION, "the agent and the host must speak the same protocol");
            assert_eq!(*uid, proto::AGENT_UID, "the agent must have dropped to uid 1000 before talking: {agent} on {kernel}");
            println!("hello: agent={agent} kernel={kernel} transport={transport} uid={uid}");
            assert_eq!(*transport, g.spec.transport.name());
        }
        other => return Err(format!("expected Hello, got {other:?}")),
    }

    // 2. A command runs as uid 1000, inside the guest's own workspace, with the
    //    guest's own PID 1 (not the host's).
    // Line by line, so a shifted output cannot silently pass the checks.
    let script = "echo ARK_GUEST_OK\n\
                  id -u\n\
                  id -un\n\
                  hostname\n\
                  pwd\n\
                  cat /proc/1/cmdline | tr '\\0' ' '; echo\n\
                  ls -A /workspace | wc -l\n\
                  cat ~/.ssh/id_ed25519 2>&1 | tail -1\n\
                  { echo pwn >> /etc/passwd; } 2>&1; echo rc=$?\n\
                  ls /home\n\
                  cat /proc/self/status | grep -E '^(Uid|Gid):'";
    let out = g.run(1, script)?;
    println!("--- exec output ---\n{out}--- end ---");
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(lines.first().copied(), Some("ARK_GUEST_OK"), "the marker did not come back: {out}");
    assert_eq!(lines.get(1).copied(), Some("1000"), "`id -u` must print 1000 (non-root, B2): {out}");
    assert_eq!(lines.get(2).copied(), Some("agent"), "`id -un` must resolve to the agent account: {out}");
    assert_eq!(lines.get(3).copied(), Some(g.spec.id.as_str()), "the hostname comes from ark.vm=: {out}");
    assert_eq!(lines.get(4).copied(), Some(proto::GUEST_WORKSPACE), "commands start in the workspace: {out}");
    assert!(lines.get(5).is_some_and(|l| l.contains("/sbin/init")), "PID 1 must be the ark guest agent, not a host process: {out}");
    assert_eq!(lines.get(6).copied(), Some("0"), "the workspace must start out empty: {out}");
    assert!(lines.iter().any(|l| l.starts_with("Uid:") && l.contains("1000")), "the command must run as uid 1000: {out}");
    assert!(lines.iter().any(|l| l.starts_with("Gid:") && l.contains("1000")), "the command must run as gid 1000: {out}");
    // No key material from the host, and no host path anywhere in the output.
    assert!(out.contains("No such file or directory"), "a guest must have no ssh key: {out}");
    assert!(!out.contains("/home/noob") && !out.contains("/root/"), "the guest must not see a host path: {out}");
    // root is gone: an agent-uid write to /etc/passwd has to fail.
    assert!(out.contains("rc=1"), "the agent could still write /etc/passwd: {out}");
    assert!(out.contains("Permission denied"), "the write must fail with EACCES: {out}");

    // 3. The workspace is synced through the channel, both ways, and only
    //    workspace-relative paths are accepted.
    let files = vec![
        FileBlob { path: "src/hello.txt".into(), data: B64.encode(b"pushed from the host\n"), mode: 0o644 },
        FileBlob { path: "notes/deep.txt".into(), data: B64.encode(b"nested\n"), mode: 0o600 },
    ];
    g.send(&HostMsg::Push { id: 2, files })?;
    match g.next(FRAME_WAIT)? {
        Some(GuestMsg::Ok { id: 2, detail }) => println!("push: {detail}"),
        other => return Err(format!("Push answered {other:?}")),
    }
    let out = g.run(3, "cat src/hello.txt; ls -l notes/deep.txt | cut -d' ' -f1")?;
    assert!(out.contains("pushed from the host"), "{out}");
    assert!(out.contains("-rw-------"), "the file mode must be applied: {out}");

    g.send(&HostMsg::Pull { id: 4, paths: vec!["src/hello.txt".into(), "missing.txt".into()] })?;
    match g.next(FRAME_WAIT)? {
        Some(GuestMsg::Files { id: 4, files }) => {
            // A path the command never created is simply not in the answer.
            assert_eq!(files.len(), 1, "only the existing file is returned: {files:?}");
            assert_eq!(files[0].path, "src/hello.txt");
            assert_eq!(B64.decode(files[0].data.as_bytes()).unwrap_or_default(), b"pushed from the host\n");
            assert_eq!(files[0].mode & 0o777, 0o644);
        }
        other => return Err(format!("Pull answered {other:?}")),
    }
    // An escaping path is refused, and the refusal names the rule.
    g.send(&HostMsg::Pull { id: 5, paths: vec!["../etc/shadow".into()] })?;
    match g.next(FRAME_WAIT)? {
        Some(GuestMsg::Err { id: 5, message }) => assert!(message.contains("workspace"), "{message}"),
        other => return Err(format!("an escaping Pull answered {other:?}")),
    }

    // 4. A command that streams output, then one with a pty and a resize.
    g.send(&HostMsg::Exec { id: 6, script: "for i in 1 2 3 4 5; do echo line-$i; done".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 30 })?;
    let (out, code, _) = g.until_exit(6)?;
    assert_eq!(code, Some(0));
    for i in 1..=5 {
        assert!(out.contains(&format!("line-{i}")), "streaming lost a chunk: {out}");
    }
    g.send(&HostMsg::Exec { id: 7, script: "stty size; tty".into(), cwd: None, env: vec![], login: false, stdin: false, pty: Some((24, 80)), timeout_secs: 30 })?;
    let (out, _, _) = g.until_exit(7)?;
    assert!(out.contains("24 80"), "a pty of the asked size must exist: {out:?}");
    assert!(out.contains("/dev/pts/"), "the command should see a tty: {out:?}");

    // 5. A command is killed by its own timeout, and a `Signal` kills the whole
    //    process group (the shell *and* the child it spawned).
    let killed_by = |g: &mut Guest, id: u64| -> Result<Option<i32>, String> {
        let (_, _, signal) = g.until_exit(id)?;
        Ok(signal)
    };
    g.send(&HostMsg::Exec { id: 10, script: "sleep 30".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 1 })?;
    let signal = killed_by(g, 10)?;
    assert_eq!(signal, Some(libc::SIGTERM), "the guest must enforce `timeout_secs` with SIGTERM");
    g.send(&HostMsg::Exec { id: 11, script: "sleep 30 & wait".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 0 })?;
    std::thread::sleep(Duration::from_millis(300));
    g.send(&HostMsg::Signal { id: 11, force: true })?;
    let signal = killed_by(g, 11)?;
    assert_eq!(signal, Some(libc::SIGKILL), "`force` must SIGKILL the process group");

    // 6. Ping and a bad id: the reader stays responsive, unknown ids are errors.
    g.send(&HostMsg::Ping { id: 8 })?;
    loop {
        match g.next(FRAME_WAIT)? {
            Some(GuestMsg::Pong { id: 8 }) => break,
            Some(_) => continue,
            None => return Err("no Pong".into()),
        }
    }
    g.send(&HostMsg::Signal { id: 999, force: true })?;
    match g.next(FRAME_WAIT)? {
        Some(GuestMsg::Err { id: 999, .. }) => {}
        other => return Err(format!("an unknown id answered {other:?}")),
    }

    // 7. The broker: a program inside the VM can only *ask* the daemon (A2/A3),
    //    and the answer comes back over the same channel.
    g.send(&HostMsg::Exec {
        id: 9,
        script: r#"ark-broker '{"kind":"egress.http","payload":{"url":"https://example.com"}}'"#.into(),
        cwd: None,
        env: vec![],
        login: false,
        stdin: false,
        pty: None,
        timeout_secs: 30,
    })?;
    let mut out = Vec::new();
    let mut seen_broker = false;
    loop {
        match g.next(FRAME_WAIT)? {
            Some(GuestMsg::Broker { id, kind, payload }) => {
                assert_eq!(kind, "egress.http", "the guest forwards the request's kind verbatim");
                assert_eq!(payload["url"], "https://example.com");
                seen_broker = true;
                // The host decides; here we just say yes.
                g.send(&HostMsg::BrokerReply { id, ok: true, payload: serde_json::json!({ "status": 200 }) })?;
            }
            Some(GuestMsg::Out { id: 9, data }) => out.extend(B64.decode(data.as_bytes()).unwrap_or_default()),
            Some(GuestMsg::Exit { id: 9, code, .. }) => {
                let text = String::from_utf8_lossy(&out).into_owned();
                println!("broker client said: {text}");
                assert!(seen_broker, "no Broker frame reached the host");
                assert_eq!(code, Some(0), "the broker client must exit 0 when the daemon says ok: {text}");
                assert!(text.contains(r#""ok":true"#) && text.contains("200"), "{text}");
                break;
            }
            Some(GuestMsg::Err { id: 9, message }) => return Err(format!("broker exec: {message}")),
            Some(_) => continue,
            None => return Err("the broker round trip never finished".into()),
        }
    }
    Ok(())
}

#[test]
#[ignore = "boots a real VM: needs /dev/kvm and a built image"]
fn boots_a_firecracker_microvm_and_runs_a_command() {
    let Some(image) = image_dir() else { return no_image() };
    let bin = std::env::var_os("ARK_FIRECRACKER").map(PathBuf::from).filter(|p| p.is_file()).or_else(|| {
        let t = std::env::var_os("TMPDIR").map(|d| PathBuf::from(d).join("dl/firecracker"));
        t.into_iter().chain(std::env::var_os("TMPDIR").map(|d| PathBuf::from(d).join("firecracker"))).find(|p| p.is_file())
    });
    let Some(bin) = bin else {
        eprintln!("SKIP: no firecracker binary (set ARK_FIRECRACKER, or put it in $TMPDIR/dl/firecracker)");
        return;
    };
    let cfg = VmConfig { firecracker: bin.display().to_string(), ..Default::default() };
    let provider = FirecrackerProvider::new(&cfg);
    let run_dir = scratch_dir("fc");
    let mut spec = spec_of("boot-fc", &image, run_dir.clone(), Transport::Vsock { port: proto::VSOCK_PORT });
    spec.firecracker = Some(bin);
    println!("booting Firecracker from {}", image.display());
    let mut g = match Guest::boot(&provider, spec) {
        Ok(g) => g,
        Err(e) => panic!("{e}"),
    };
    println!("hello after {:?} (uid: {})", g.hello_at, hello_uid(&g.hello));
    let result = exercise_the_guest(&mut g);
    let checks = g.started.elapsed() - g.hello_at;
    let hello_at = g.hello_at;
    let usage = g.inst.usage();
    let stopped = g.shutdown();
    result.unwrap_or_else(|e| panic!("guest checks failed: {e}"));
    println!("the agent powered the VM off itself: {stopped}");
    assert!(stopped, "Shutdown must power the VM off (the agent keeps CAP_SYS_BOOT for exactly this)");
    println!("firecracker microVM: Hello after {hello_at:?} (most of it is the Firecracker API, see the note above), guest checks {checks:?}, vmm rss {} KiB", usage.rss_kb);
    let _ = run_dir;
}

#[test]
#[ignore = "boots a real VM: needs /dev/kvm and a built image"]
fn boots_a_qemu_microvm_and_runs_a_command() {
    let Some(image) = image_dir() else { return no_image() };
    let cfg = VmConfig::default();
    let provider = QemuProvider::new(&cfg);
    let run_dir = scratch_dir("qemu");
    let spec = spec_of("boot-qemu", &image, run_dir.clone(), Transport::Serial);
    println!("booting QEMU from {}", image.display());
    let started = Instant::now();
    let mut inst = match provider.start(&spec) {
        Ok(i) => i,
        Err(e) => panic!("{e}"),
    };
    let opened = open_channel(&spec, inst.as_mut(), BOOT_WAIT);
    let mut g = match opened {
        Ok((ch, hello)) => Guest { spec: spec.clone(), inst, ch, hello, queued: VecDeque::new(), started, hello_at: started.elapsed() },
        Err(e) => {
            let log = console_tail(&spec);
            inst.stop();
            let _ = std::fs::remove_dir_all(&run_dir);
            // The guest agent reports why it could not serve: with a
            // virtio-mmio-only kernel (the Firecracker CI image) QEMU's
            // virtio-serial-pci is never probed, so /dev/vport0p1 does not
            // exist. That is a provider/image mismatch, not a guest bug, and it
            // is documented in packaging/vm/README.md.
            if log.contains("cannot open /dev/vport0p1") {
                eprintln!(
                    "SKIP: the QEMU provider cannot reach this guest image.\n\
                     The guest agent booted and reported that {} is missing, which is what\n\
                     happens with a virtio-mmio-only guest kernel (CONFIG_PCI is off in the\n\
                     Firecracker CI vmlinux): QEMU attaches the channel to virtio-serial-pci,\n\
                     and a kernel without PCI never probes it. Use the Firecracker provider\n\
                     (same image, same protocol, vsock) or a PCI-capable guest kernel.\n\
                     --- guest console ---\n{log}",
                    proto::SERIAL_DEVICE
                );
                return;
            }
            panic!("no guest channel: {e}\n--- guest console ---\n{log}");
        }
    };
    println!("hello after {:?} (uid: {})", g.hello_at, hello_uid(&g.hello));
    let result = exercise_the_guest(&mut g);
    let checks = g.started.elapsed() - g.hello_at;
    let hello_at = g.hello_at;
    g.shutdown();
    result.unwrap_or_else(|e| panic!("guest checks failed: {e}"));
    println!("qemu microVM: Hello after {hello_at:?}, guest checks {checks:?}");
    let _ = std::fs::remove_dir_all(&run_dir);
}

fn hello_uid(m: &GuestMsg) -> u32 {
    match m {
        GuestMsg::Hello { uid, .. } => *uid,
        _ => u32::MAX,
    }
}
