# The ark microVM guest image

One kernel and one initramfs. Boot them and the kernel starts the ark guest
agent as PID 1; the agent mounts what it needs, drops to uid 1000 and speaks
the single channel protocol (`crates/ark-vm/src/proto.rs`) with the host.

```
packaging/vm/build-image.sh --out "$TMPDIR/ark-vm-image"
# -> …/ark-vm-image/vmlinux
# -> …/ark-vm-image/initramfs.cpio.gz
# -> …/ark-vm-image/manifest.json
```

Current artefacts on this machine: `vmlinux` 38 355 216 B (34 MiB),
`initramfs.cpio.gz` ≈ 4.3 MiB (Alpine 3.20.3 + the static agent).

## Why the guest root is an initramfs (B2)

The whole guest root file system is a compressed cpio archive that the kernel
unpacks into RAM and mounts read-only-ish as `/`. That is deliberate:

* **Nothing the VM writes can survive it.** There is no block device at all — no
  `PUT /drives` under Firecracker, no `-drive` under QEMU — so a tool cannot
  corrupt an image, cannot persist a payload across VMs and cannot fill a host
  disk. The only writable places are tmpfs (`/tmp`, sized by `ark.disk_mb`) and
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
| `/sbin/init` | `ark-vm-guest`, the static agent; the kernel's `rdinit=` target |
| `/usr/bin/ark-vm-guest` | the same binary, for `ark-vm-guest version` |
| `/usr/bin/ark-broker` | symlink to it; the in-VM broker client (`broker-send`) |
| `/home/agent` | home of the only user that ever runs code (uid/gid 1000) |
| `/workspace` | the synced workspace (`ark.workspace=`), owned by the agent |
| `/run/ark/broker.sock` | where an in-VM program asks the daemon for egress / a privileged command |
| `/dev`, `/proc`, `/sys`, `/dev/pts`, `/dev/shm`, `/tmp` | mounted by the agent as PID 1, before the privilege drop |

`/etc/passwd` and `/etc/group` get exactly one added account:
`agent:x:1000:1000:ark agent:/home/agent:/bin/sh`. Nothing in the guest runs as
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
and `/run/ark`, which the agent chowns to uid 1000 right before dropping.

### Kernel parameters the agent reads

`/proc/cmdline`, written by `provider::qemu::cmdline_append` (shared with the
Firecracker provider, so both boot the same guest):

| parameter | meaning |
| --- | --- |
| `ark.vm=` | VM id, also the hostname |
| `ark.tier=` | trust tier of the VM (`owner`, `stranger`, …) — logged, never trusted by the guest |
| `ark.channel=` | `virtio-serial` or `vsock` |
| `ark.workspace=` | absolute guest path of the workspace |
| `ark.disk_mb=` | size of the `/tmp` tmpfs (also `RLIMIT_FSIZE`) |
| `ark.nproc=` | `RLIMIT_NPROC` for uid 1000 (fork bombs die inside the VM) |
| `ark.nofile=` | `RLIMIT_NOFILE` |
| `ark.workspace_ro=1` | the agent refuses every `Push` and every write (B2) |

Anything that is not a plain, absolute path (or a sane number) is *ignored*, not
reinterpreted: `ark.workspace=../../etc` leaves `/workspace` in place.

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
export TMPDIR=/var/tmp/ark            # or anywhere writable; nothing goes to /tmp
packaging/vm/build-image.sh --out "$TMPDIR/ark-vm-image"

# 2. Offline: reuse the artefacts already in --out, or point at local copies.
packaging/vm/build-image.sh --out "$TMPDIR/ark-vm-image" \
    --kernel /path/to/vmlinux --rootfs /path/to/alpine-minirootfs-3.20.3-x86_64.tar.gz

# 3. Fast loop while developing the agent: build it yourself and hand it over.
cargo build -p ark-vm --bin ark-vm-guest --release --target x86_64-unknown-linux-musl
packaging/vm/build-image.sh --out "$TMPDIR/ark-vm-image" \
    --agent target/x86_64-unknown-linux-musl/release/ark-vm-guest
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
C compiler configured for musl (the `ring` dependency of `ark-net` compiles C),
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
  "agent":     { "sha256": "136a…", "version": "ark-vm-guest 0.1.0 protocol 1",
                 "target": "x86_64-unknown-linux-musl", "init": "/sbin/init" },
  "alpine":    { "version": "3.20.3", "url": "…", "sha256": "d4e6…" }
}
```

`image_version` is `ark_vm::IMAGE_VERSION`: a provider refuses an image whose
version (or agent `Hello` protocol version) it does not speak, instead of
booting a guest that answers in an older protocol.

## Using it

```sh
export ARK_VM_IMAGE_DIR="$TMPDIR/ark-vm-image"     # what the boot test reads
cargo test -p ark-vm --test boot_vm -- --ignored --nocapture
```

Inside the VM, the only way out is the agent:

```sh
# ask the daemon for egress or a privileged command; the host decides
ark-broker '{"kind":"egress.http","payload":{"url":"https://example.com"}}'
# -> {"ok":true,"payload":{…}}   exit 0, or {"ok":false,"error":"…"} exit 1
```

## One interface for every backend

`ark_vm::unify::IsolatedEnv` is the interface every execution environment
implements, and the microVM is its reference implementation: `caps()` reports the
wall (a microVM, via firecracker/qemu), a workspace that arrives by copy+sync, real
snapshot/undo points, the broker, and uid 1000. The other backends are adapters
(`ark_tools::exec::unify`, `open` / `caps_of`) with honest `EnvCaps`: docker,
podman and singularity bind-mount the host workspace, ssh/modal/daytona/vercel are
copies, and none of them claims a level stronger than the single table in
`ark_vm::isolation` gives it — a weaker level always carries its warning. Where a
backend cannot support a promise it says so instead of faking it: `snapshot()`
returns `None` (and `undo()` has nothing to restore) on everything except the
microVM, and `open` returns an error naming the reason rather than silently
falling back to running on the host.
