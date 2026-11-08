# The SE Agent microVM guest image

One kernel and one initramfs. Boot them and the kernel starts the SE Agent guest
agent as PID 1; the agent mounts what it needs, drops to uid 1000 and speaks
the single channel protocol (`crates/seagent-vm/src/proto.rs`) with the host.

```
packaging/vm/build-image.sh --out "$TMPDIR/seagent-vm-image"
# -> …/seagent-vm-image/vmlinux
# -> …/seagent-vm-image/initramfs.cpio.gz
# -> …/seagent-vm-image/manifest.json
```

Current artefacts on this machine: `vmlinux` 38 355 216 B (34 MiB),
`initramfs.cpio.gz` ≈ 4.3 MiB (Alpine 3.20.3 + the static agent).

## Why the guest root is an initramfs (B2)

The whole guest root file system is a compressed cpio archive that the kernel
unpacks into RAM and mounts read-only-ish as `/`. That is deliberate:

* **Nothing the VM writes can survive it.** There is no block device at all — no
  `PUT /drives` under Firecracker, no `-drive` under QEMU — so a tool cannot
  corrupt an image, cannot persist a payload across VMs and cannot fill a host
  disk. The only writable places are tmpfs (`/tmp`, sized by `seagent.disk_mb`) and
  the workspace directory, both of which vanish with the VM.
* **The VM cannot see the host file system.** The workspace is *synced* through
  the agent (`Push`/`Pull` frames), never mounted: there is no virtio-fs, 9p or
  bind mount from the guest to a host path, so a guest-side compromise cannot
  walk out of the share (`Workspace` in `provider/mod.rs` says the same thing).
* **The image is immutable and content-addressed.** `manifest.json` pins the
  sha256 of the kernel, the initramfs and the agent, so a VM either runs the
  bits that were reviewed or refuses to start.

The price is that the image is rebuilt to change anything in the guest — which
is the point: a guest the tools cannot modify is a guest that cannot be
tampered with.

## What is inside

| path | what |
| --- | --- |
| `/sbin/init` | `seagent-vm-guest`, the static agent; the kernel's `rdinit=` target |
| `/usr/bin/seagent-vm-guest` | the same binary, for `seagent-vm-guest version` |
| `/usr/bin/seagent-broker` | symlink to it; the in-VM broker client (`broker-send`) |
| `/home/agent` | home of the only user that ever runs code (uid/gid 1000) |
| `/workspace` | the synced workspace (`seagent.workspace=`), owned by the agent |
| `/run/seagent/broker.sock` | where an in-VM program asks the daemon for egress / a privileged command |
| `/dev`, `/proc`, `/sys`, `/dev/pts`, `/dev/shm`, `/tmp` | mounted by the agent as PID 1, before the privilege drop |

`/etc/passwd` and `/etc/group` get exactly one added account:
`agent:x:1000:1000:seagent agent:/home/agent:/bin/sh`. Nothing in the guest runs as
root after the agent's `setuid(1000)`; the single capability the agent keeps is
`CAP_SYS_BOOT`, so it can honour `Shutdown` by powering the VM off (ACPI S5, as
QEMU provides) or, where the firmware has no power-management block (Firecracker's
FADT has `PM1a_CNT_BLK = 0`, so `reboot(RB_POWER_OFF)` would only halt the
kernel), by resetting the guest — which is what both VMMs act on: Firecracker
stops the process, QEMU runs with `-no-reboot`. Measured: Firecracker exits with
status 0 after the guest resets, and keeps running after `RB_POWER_OFF`.

Every file in the archive is owned by `root:root` (`cpio --owner 0:0`): the
rootfs is unpacked as the *build* user, and without that the agent's own uid
would own `/etc/passwd` — i.e. the unprivileged side could rewrite its own user
database (B2). The only things the guest owns are `/workspace`, `/home/agent`
and `/run/seagent`, which the agent chowns to uid 1000 right before dropping.

### Kernel parameters the agent reads

`/proc/cmdline`, written by `provider::qemu::cmdline_append` (shared with the
Firecracker provider, so both boot the same guest):

| parameter | meaning |
| --- | --- |
| `seagent.vm=` | VM id, also the hostname |
| `seagent.tier=` | trust tier of the VM (`owner`, `stranger`, …) — logged, never trusted by the guest |
| `seagent.channel=` | `virtio-serial` or `vsock` |
| `seagent.workspace=` | absolute guest path of the workspace |
| `seagent.disk_mb=` | size of the `/tmp` tmpfs (also `RLIMIT_FSIZE`) |
| `seagent.nproc=` | `RLIMIT_NPROC` for uid 1000 (fork bombs die inside the VM) |
| `seagent.nofile=` | `RLIMIT_NOFILE` |
| `seagent.workspace_ro=1` | the agent refuses every `Push` and every write (B2) |

Anything that is not a plain, absolute path (or a sane number) is *ignored*, not
reinterpreted: `seagent.workspace=../../etc` leaves `/workspace` in place.

## Kernel

The image uses the Firecracker CI `vmlinux` 5.10.223
(`https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223`,
sha256 `2284737572…0c1e65`). It is chosen because it is small, boots in well
under a second and has everything the agent needs **built in** — devtmpfs,
`virtio_console`, `virtio_mmio`, AF_VSOCK, tmpfs, devpts — with no modules to
load from an unprivileged guest.

Two consequences worth knowing before you change the provider:

* it is a **virtio-mmio** kernel: `CONFIG_PCI` is off, so Firecracker's
  virtio-mmio devices work and QEMU's virtio-*pci* devices are simply never
  probed by the guest (`/dev/vport0p1` never appears). Under QEMU the agent can
  only use AF_VSOCK, which needs `vhost-vsock` and `/dev/vsock` on the host, or
  a QEMU machine that offers virtio-mmio (and QEMU's `microvm` machine does not
  currently boot this kernel — it panics in `console_init`).
* the distro kernels (Alpine `linux-virt`, Debian, Ubuntu) have the virtio
  drivers as *modules*, so they cannot be used without shipping `/lib/modules`
  in the initramfs and loading them as root. That is not what this image does.

## Rebuilding

```sh
# 1. Online, from scratch: downloads the kernel + Alpine minirootfs (pinned
#    sha256), builds the agent for musl, packs the initramfs, writes the manifest.
export TMPDIR=/var/tmp/seagent            # or anywhere writable; nothing goes to /tmp
packaging/vm/build-image.sh --out "$TMPDIR/seagent-vm-image"

# 2. Offline: reuse the artefacts already in --out, or point at local copies.
packaging/vm/build-image.sh --out "$TMPDIR/seagent-vm-image" \
    --kernel /path/to/vmlinux --rootfs /path/to/alpine-minirootfs-3.20.3-x86_64.tar.gz

# 3. Fast loop while developing the agent: build it yourself and hand it over.
cargo build -p seagent-vm --bin seagent-vm-guest --release --target x86_64-unknown-linux-musl
packaging/vm/build-image.sh --out "$TMPDIR/seagent-vm-image" \
    --agent target/x86_64-unknown-linux-musl/release/seagent-vm-guest
```

Properties of the script:

* **idempotent** — re-running yields the same layout; downloads are skipped when
  the file already has the pinned sha256 (a mismatch is re-downloaded, never
  accepted);
* **no root, no sudo** — it only writes under `--out`; the rootfs is unpacked
  with `--no-same-owner`, `/dev` is devtmpfs at runtime anyway;
* **offline afterwards** — `vmlinux`, `initramfs.cpio.gz` and `manifest.json`
  are self-contained; a VM needs nothing else and never fetches anything;
* `--help` documents every flag.

The agent must be **static** (`x86_64-unknown-linux-musl`, or a
`+crt-static` GNU build): the guest has no dynamic loader. A musl target needs a
C compiler configured for musl (the `ring` dependency of `seagent-net` compiles C),
so either install `musl-gcc` or export

```sh
export CC_x86_64_unknown_linux_musl=clang AR_x86_64_unknown_linux_musl=llvm-ar
```

The script falls back to a `+crt-static` GNU build (same static binary, just
linked against glibc) only if the musl build fails, and says so loudly; the
manifest records which target was used.

## manifest.json

```json
{
  "image_version": 1,
  "built_at": "2026-11-04T12:48:36Z",
  "kernel":    { "path": "vmlinux", "sha256": "2284…", "size": 38355216, "source_url": "…" },
  "initramfs": { "path": "initramfs.cpio.gz", "sha256": "69f0…", "size": 4495035 },
  "agent":     { "sha256": "136a…", "version": "seagent-vm-guest 0.1.0 protocol 1",
                 "target": "x86_64-unknown-linux-musl", "init": "/sbin/init" },
  "alpine":    { "version": "3.20.3", "url": "…", "sha256": "d4e6…" }
}
```

`image_version` is `seagent_vm::IMAGE_VERSION`: a provider refuses an image whose
version (or agent `Hello` protocol version) it does not speak, instead of
booting a guest that answers in an older protocol.

## Using it

```sh
export SEAGENT_VM_IMAGE_DIR="$TMPDIR/seagent-vm-image"     # what the boot test reads
cargo test -p seagent-vm --test boot_vm -- --ignored --nocapture
```

Inside the VM, the only way out is the agent:

```sh
# ask the daemon for egress or a privileged command; the host decides
seagent-broker '{"kind":"egress.http","payload":{"url":"https://example.com"}}'
# -> {"ok":true,"payload":{…}}   exit 0, or {"ok":false,"error":"…"} exit 1
```

## Booting it on other hosts

The guest is always Linux; each host OS boots it with its own hypervisor
(`crates/seagent-vm/src/provider/`, chosen by `isolation::Capabilities::vm_candidates`):

| host | provider (auto order) | needs from the image | channel (`seagent.channel=`) |
| --- | --- | --- | --- |
| Linux | Firecracker → QEMU-KVM | `vmlinux` + `initramfs.cpio.gz` (unchanged) | `vsock` / `virtio-serial` |
| Windows | QEMU+WHPX (TCG fallback, warned) | same files; PCI kernel for virtio-serial | `virtio-serial` over 127.0.0.1 TCP |
| Windows | Hyper-V (Gen 2, elevated) | **raw UEFI disk** → `disk.vhdx` via `qemu-img convert -O vhdx` (wired) | `uart` (`/dev/ttyS1`, named pipe) |
| Win / macOS / Linux | VirtualBox | **raw UEFI disk** → `disk.vdi` via `VBoxManage convertfromraw` (wired), attached immutable | `uart` (unix socket / named pipe) |
| macOS | vfkit (Virtualization.framework) → QEMU+HVF | **arm64** kernel `Image` + initramfs on Apple Silicon (virtio-PCI + vsock built in) | `vsock` (no preface) |
| Android | AVF `vm run` (crosvm, pKVM) | arm64 kernel + initramfs | `vsock` (host AF_VSOCK to the CID) |
| iOS | none (platform policy) | — | — |

Not built by `build-image.sh` yet: the arm64 variant and the raw UEFI disk (`disk.raw`,
an ESP that boots the same kernel + initramfs with `seagent.channel=uart`). Until they
exist, those providers report the missing artefact instead of booting.

## One interface for every backend

`seagent_vm::unify::IsolatedEnv` is the interface every execution environment
implements, and the microVM is its reference implementation: `caps()` reports the
wall (a microVM, via firecracker/qemu), a workspace that arrives by copy+sync, real
snapshot/undo points, the broker, and uid 1000. The other backends are adapters
(`seagent_tools::exec::unify`, `open` / `caps_of`) with honest `EnvCaps`: docker,
podman and singularity bind-mount the host workspace, ssh/modal/daytona/vercel are
copies, and none of them claims a level stronger than the single table in
`seagent_vm::isolation` gives it — a weaker level always carries its warning. Where a
backend cannot support a promise it says so instead of faking it: `snapshot()`
returns `None` (and `undo()` has nothing to restore) on everything except the
microVM, and `open` returns an error naming the reason rather than silently
falling back to running on the host.
