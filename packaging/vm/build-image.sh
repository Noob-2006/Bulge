#!/usr/bin/env bash
# Build the seagent microVM guest image: one kernel + one read-only initramfs that
# has the guest agent (`seagent-vm-guest`) as `/sbin/init` — and, with
# `--format disk`, a raw UEFI disk that boots the same guest without a VMM-side
# kernel loader (VirtualBox, Hyper-V).
#
# Everything the VM needs is in these files: the guest root is an initramfs
# mounted by the kernel, so there is no root disk, no host directory and no bind
# mount inside the VM (B2). `seagent.workspace_ro=1` and the agent's privilege drop
# are enforced by the guest, on top of that. The disk is only a carrier: its ESP
# holds one EFI application (the kernel, with the initramfs and the command line
# built in), and nothing in the guest ever mounts it.
#
# The script is idempotent, needs no root and never touches anything outside
# `--out DIR`: downloads land in `DIR/dl`, the unpacked rootfs and the kernel
# tree in `DIR/build`, the artefacts in `DIR`. Re-running with the artefacts in
# place skips the downloads (after a sha256 check) and rebuilds the initramfs
# from scratch, so a second run with `--agent` is the offline workflow.
#
# Usage: packaging/vm/build-image.sh [--out DIR] [--arch x86_64|aarch64]
#                                    [--format initramfs|disk] [--build-kernel]
#                                    [--agent PATH] [--kernel PATH] [--rootfs PATH]
#                                    [--kernel-src PATH] [--target TRIPLE] [--help]
set -euo pipefail

# x86_64 direct-boot default: the Firecracker CI kernel (virtio-mmio, no PCI).
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223"
# Firecracker CI 5.10.223: built for virtio-mmio (Firecracker) and, importantly,
# with virtio and devtmpfs built in — no modules, so nothing has to be loaded
# from inside an unprivileged guest.
KERNEL_SHA256="22847375721aceea63d934c28f2dfce4670b6f52ec904fae19f5145a970c1e65"
# Everything else (arm64, the disk, --build-kernel) is built from this pinned
# kernel.org tarball with packaging/vm/kernel/*.config. sha256 as published in
# https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc (6.12 = LTS).
LINUX_VERSION="6.12.114"
LINUX_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.xz"
LINUX_SHA256="7a8589912bd7a8adb07fed074283652cf482a35facef8954554654f0154b4af3"
ALPINE_VERSION="3.20.3"
ALPINE_SHA256_x86_64="d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c"
ALPINE_SHA256_aarch64="041fa34a81788242df9e78fa69b97ab45b8ec47ddbf88864755610414a7bf3de"
# What VirtualBox / Hyper-V boot with: the providers cannot pass a command line,
# so it is baked into the disk's kernel (CONFIG_CMDLINE, forced). ttyS0 = COM1
# (console log), the channel is COM2 = /dev/ttyS1 (proto::UART_DEVICE). Per-VM
# values (vm id, tier, limits) arrive in the host's `Limits` message instead.
DISK_CMDLINE_BASE="quiet rdinit=/sbin/init seagent.channel=uart seagent.workspace=/workspace"
ESP_MIB=64

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

usage() {
	cat <<'EOF'
seagent microVM guest image builder

  build-image.sh [options]

Builds a kernel + initramfs pair that boots into the seagent guest agent
(`seagent-vm-guest` installed as /sbin/init), for x86_64 or aarch64, and
optionally a raw UEFI disk of the same guest. No root, no sudo, no writes
outside --out.

Options:
  --out DIR        Where to put the artefacts (default: $TMPDIR/seagent-vm-image,
                   or $TMPDIR/seagent-vm-image-aarch64 for --arch aarch64).
                   Contains: vmlinux, initramfs.cpio.gz, manifest.json, disk.raw
                   (--format disk), and the dl/ download cache + build/ tree.
  --arch ARCH      Guest architecture: x86_64 (default) or aarch64 (Apple
                   Silicon: vfkit / QEMU+HVF; Android AVF; arm64 Linux hosts).
                   Env: SEAGENT_VM_ARCH.
  --format FMT     initramfs (default): vmlinux + initramfs.cpio.gz, booted
                   directly by Firecracker / QEMU / vfkit / crosvm.
                   disk: the same, plus disk.raw — a GPT disk whose FAT32 ESP
                   holds \EFI\BOOT\BOOTX64.EFI (BOOTAA64.EFI on aarch64): the
                   kernel's EFI stub with the initramfs and the command line
                   built in, for VirtualBox and Hyper-V (`exec.vm.disk_image`).
                   Env: SEAGENT_VM_FORMAT.
  --build-kernel   Build the direct-boot kernel from source on x86_64 too (a
                   virtio-PCI kernel: QEMU's virtio-serial then works). aarch64
                   and the disk always build from source.
  --agent PATH     Use this prebuilt seagent-vm-guest instead of building it
                   (the offline path, and how tests inject a known binary).
  --kernel PATH    Use this direct-boot kernel instead of downloading/building
                   it. A local copy is never fetched again.
  --kernel-src P   Use this linux-*.tar.xz instead of downloading it.
  --rootfs PATH    Use this Alpine minirootfs tarball instead of downloading it.
  --target TRIPLE  Rust target for the agent (default: <arch>-unknown-linux-musl;
                   the binary must be static to run inside the guest).
  --help, -h       This text.

Environment:
  TMPDIR           Default --out lives under it.
  CARGO            Cargo binary to use (default: cargo).
  CC_<triple>      Passed through to cargo; a musl target needs a C compiler for
                   the musl libc (musl-gcc, or clang with musl headers).
  CROSS_COMPILE    Kernel cross toolchain prefix. Default when the guest arch is
                   not the host's: <arch>-linux-gnu- if that gcc is installed.
  LLVM=1           Build the kernel with clang/lld instead (cross-compiles
                   without a cross gcc).
  JOBS             Parallel kernel build jobs (default: nproc).

Kernel build needs (Debian/Ubuntu): build-essential flex bison bc libelf-dev
xz-utils cpio python3, plus gcc-aarch64-linux-gnu to cross-build arm64 on x86_64
(or gcc-x86-64-linux-gnu the other way round).

Output: prints the absolute paths of the kernel, the initramfs (and disk.raw),
then exits 0. The image is self-contained and stays valid offline.

Guest layout baked into the initramfs:
  /sbin/init, /usr/bin/seagent-vm-guest   the agent (static), PID 1
  /usr/bin/seagent-broker                 symlink to it (in-VM broker client)
  /home/agent                         uid/gid 1000, the only user that runs code
  /etc/passwd, /etc/group             `agent:x:1000:1000`
EOF
}

die() {
	printf 'build-image: %s\n' "$*" >&2
	exit 1
}
note() { printf 'build-image: %s\n' "$*" >&2; }

OUT=""
AGENT=""
KERNEL=""
KERNEL_SRC_TARBALL=""
ROOTFS=""
ARCH="${SEAGENT_VM_ARCH:-x86_64}"
FORMAT="${SEAGENT_VM_FORMAT:-initramfs}"
BUILD_KERNEL=0
TARGET="${AGENT_TARGET:-}"
TARGET_EXPLICIT=0

while [ $# -gt 0 ]; do
	case "$1" in
	--out)
		[ $# -ge 2 ] || die "--out needs a directory"
		OUT="$2"
		shift 2
		;;
	--arch)
		[ $# -ge 2 ] || die "--arch needs x86_64 or aarch64"
		ARCH="$2"
		shift 2
		;;
	--format)
		[ $# -ge 2 ] || die "--format needs initramfs or disk"
		FORMAT="$2"
		shift 2
		;;
	--build-kernel)
		BUILD_KERNEL=1
		shift
		;;
	--agent)
		[ $# -ge 2 ] || die "--agent needs a file"
		AGENT="$2"
		shift 2
		;;
	--kernel)
		[ $# -ge 2 ] || die "--kernel needs a file"
		KERNEL="$2"
		shift 2
		;;
	--kernel-src)
		[ $# -ge 2 ] || die "--kernel-src needs a linux-*.tar.xz"
		KERNEL_SRC_TARBALL="$2"
		shift 2
		;;
	--rootfs)
		[ $# -ge 2 ] || die "--rootfs needs a tarball"
		ROOTFS="$2"
		shift 2
		;;
	--target)
		[ $# -ge 2 ] || die "--target needs a triple"
		TARGET="$2"
		TARGET_EXPLICIT=1
		shift 2
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		die "unknown option '$1' (see --help)"
		;;
	esac
done

case "$ARCH" in
x86_64 | amd64)
	ARCH=x86_64
	KARCH=x86_64
	KCONFIG_ARCH=x86_64.config
	ALPINE_SHA256="$ALPINE_SHA256_x86_64"
	EFI_NAME=BOOTX64.EFI
	DISK_CONSOLE=ttyS0
	;;
aarch64 | arm64)
	ARCH=aarch64
	KARCH=arm64
	KCONFIG_ARCH=arm64.config
	ALPINE_SHA256="$ALPINE_SHA256_aarch64"
	EFI_NAME=BOOTAA64.EFI
	# VirtualBox/Hyper-V on arm64 expose PL011 UARTs (ttyAMA*), see README.
	DISK_CONSOLE=ttyAMA0
	;;
*) die "--arch '$ARCH': use x86_64 or aarch64" ;;
esac
case "$FORMAT" in
initramfs | disk) ;;
*) die "--format '$FORMAT': use initramfs or disk" ;;
esac
DEFAULT_TARGET="$ARCH-unknown-linux-musl"
[ -n "$TARGET" ] || TARGET="$DEFAULT_TARGET"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/$ARCH/alpine-minirootfs-$ALPINE_VERSION-$ARCH.tar.gz"
DISK_CMDLINE="console=$DISK_CONSOLE $DISK_CMDLINE_BASE"

# Which kernel the direct-boot `vmlinux` is: the pinned Firecracker CI binary
# (x86_64 default), a local file, or our own build.
if [ -n "$KERNEL" ]; then
	KERNEL_MODE=local
elif [ "$ARCH" = aarch64 ] || [ "$BUILD_KERNEL" = 1 ]; then
	KERNEL_MODE=source
else
	KERNEL_MODE=firecracker
fi
NEED_KERNEL_TREE=0
if [ "$KERNEL_MODE" = source ] || [ "$FORMAT" = disk ]; then
	NEED_KERNEL_TREE=1
fi

if [ -z "$OUT" ]; then
	: "${TMPDIR:=$HOME/.cache}"
	OUT="$TMPDIR/seagent-vm-image"
	[ "$ARCH" = x86_64 ] || OUT="$OUT-$ARCH"
fi
mkdir -p "$OUT/dl" "$OUT/build"
OUT="$(cd -- "$OUT" && pwd)"
DL="$OUT/dl"
ROOT="$OUT/build/root"
KERNEL_OUT="$OUT/vmlinux"
INITRAMFS_OUT="$OUT/initramfs.cpio.gz"
DISK_OUT="$OUT/disk.raw"

for tool in cpio gzip tar sha256sum find sed; do
	command -v "$tool" >/dev/null 2>&1 || die "'$tool' is required but not installed"
done

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# Fetch a pinned artefact unless a file with the expected hash is already there.
# A mismatch is never ignored: a wrong kernel is a wrong VM.
fetch() {
	local url="$1" want="$2" dest="$3"
	if [ -f "$dest" ]; then
		if [ "$(sha256_of "$dest")" = "$want" ]; then
			note "$(basename "$dest") already present (sha256 ok), not downloading"
			return 0
		fi
		note "$(basename "$dest") has the wrong sha256, downloading again"
		rm -f "$dest"
	fi
	note "downloading $url"
	curl -fsSL --retry 3 --connect-timeout 20 -o "$dest.part" "$url" || die "download failed: $url"
	local got
	got="$(sha256_of "$dest.part")"
	[ "$got" = "$want" ] || {
		rm -f "$dest.part"
		die "sha256 mismatch for $url: expected $want, got $got"
	}
	mv -f "$dest.part" "$dest"
}

check_agent() {
	[ -f "$AGENT" ] || die "--agent $AGENT does not exist"
	local desc
	desc="$(file -b "$AGENT" 2>/dev/null || true)"
	case "$desc" in
	*"statically linked"* | *"static-pie"*) ;;
	*) note "WARNING: $AGENT does not look statically linked; the guest has no dynamic loader" ;;
	esac
	# A wrong-architecture init is a guest that panics at boot: refuse it.
	case "$ARCH:$desc" in
	x86_64:*aarch64* | x86_64:*"ARM "* | aarch64:*x86-64*)
		die "$AGENT is not an $ARCH binary ($desc)"
		;;
	esac
}
# A prebuilt agent is checked now, before any long kernel build.
AGENT_CHECKED=0
if [ -n "$AGENT" ]; then
	check_agent
	AGENT_CHECKED=1
fi

# ── preflight for a kernel build (fail before the long steps) ─────────────────
HOST_ARCH="$(uname -m)"
[ "$HOST_ARCH" = arm64 ] && HOST_ARCH=aarch64
KMAKE=()
if [ "$NEED_KERNEL_TREE" = 1 ]; then
	PYTHON="$(command -v python3 || true)"
	[ -n "$PYTHON" ] || die "python3 is required (packaging/vm/mkdisk.py, kernel build)"
	for f in mkdisk.py kernel/common.config "kernel/$KCONFIG_ARCH"; do
		[ -f "$SCRIPT_DIR/$f" ] || die "$SCRIPT_DIR/$f is missing (an incomplete copy of packaging/vm?)"
	done
	missing=()
	for tool in make flex bison bc perl xz; do
		command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
	done
	if [ -z "${LLVM:-}" ]; then
		if [ "$ARCH" != "$HOST_ARCH" ] && [ -z "${CROSS_COMPILE:-}" ] && command -v "$ARCH-linux-gnu-gcc" >/dev/null 2>&1; then
			CROSS_COMPILE="$ARCH-linux-gnu-"
		fi
		if [ "$ARCH" != "$HOST_ARCH" ] && [ -z "${CROSS_COMPILE:-}" ]; then
			missing+=("$ARCH-linux-gnu-gcc (apt: gcc-${ARCH//_/-}-linux-gnu, or set LLVM=1)")
		elif ! command -v "${CROSS_COMPILE:-}gcc" >/dev/null 2>&1; then
			missing+=("${CROSS_COMPILE:-}gcc")
		fi
	else
		command -v clang >/dev/null 2>&1 || missing+=("clang (LLVM=1)")
		command -v ld.lld >/dev/null 2>&1 || missing+=("ld.lld (LLVM=1)")
	fi
	# x86_64 kernels always run objtool, which links libelf.
	if [ "$ARCH" = x86_64 ] && ! printf '#include <gelf.h>\n' | "${HOSTCC:-cc}" -E -x c - >/dev/null 2>&1; then
		missing+=("libelf headers (apt: libelf-dev)")
	fi
	# CONFIG_INITRAMFS_SOURCE is a space-separated list: the path must have no blanks.
	case "$OUT" in *[[:space:]\"]*) die "--out '$OUT' contains blanks or quotes; the kernel's INITRAMFS_SOURCE cannot name it" ;; esac
	if [ ${#missing[@]} -gt 0 ]; then
		note "building the kernel needs, and this host is missing:"
		for m in "${missing[@]}"; do note "  - $m"; done
		die "install them (Debian/Ubuntu: build-essential flex bison bc libelf-dev; gcc-aarch64-linux-gnu to cross-build arm64), or pass --kernel and use --format initramfs"
	fi
	KMAKE=(make -j"${JOBS:-$(nproc 2>/dev/null || echo 2)}" ARCH="$KARCH" KBUILD_BUILD_USER=seagent KBUILD_BUILD_HOST=build-image)
	[ -n "${CROSS_COMPILE:-}" ] && KMAKE+=(CROSS_COMPILE="$CROSS_COMPILE")
	[ -n "${LLVM:-}" ] && KMAKE+=(LLVM="$LLVM")
	# Reproducible kernel: no build clock in the version string.
	export KBUILD_BUILD_TIMESTAMP="${SOURCE_DATE_EPOCH:+@$SOURCE_DATE_EPOCH}"
	# Explicitly UTC: a bare "1970-01-01" is local midnight, i.e. a *negative* epoch east of
	# Greenwich (-28800 in UTC+8), and gen_init_cpio then fails with "Timestamp out of range
	# for cpio format" while packing the kernel's built-in initramfs.
	[ -n "$KBUILD_BUILD_TIMESTAMP" ] || export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 UTC"
fi

# ── kernel source tree (only when something is built from source) ────────────
KSRC="$OUT/build/linux-$LINUX_VERSION"
KOBJ="$OUT/build/kobj-$ARCH"
if [ "$NEED_KERNEL_TREE" = 1 ]; then
	if [ -n "$KERNEL_SRC_TARBALL" ]; then
		[ -f "$KERNEL_SRC_TARBALL" ] || die "--kernel-src $KERNEL_SRC_TARBALL does not exist"
		LINUX_TARBALL="$KERNEL_SRC_TARBALL"
		[ "$(sha256_of "$LINUX_TARBALL")" = "$LINUX_SHA256" ] || note "WARNING: --kernel-src sha256 is $(sha256_of "$LINUX_TARBALL"), not the pinned $LINUX_SHA256"
	else
		LINUX_TARBALL="$DL/linux-$LINUX_VERSION.tar.xz"
		fetch "$LINUX_URL" "$LINUX_SHA256" "$LINUX_TARBALL"
	fi
	LINUX_TARBALL_SHA="$(sha256_of "$LINUX_TARBALL")"
	if [ "$(cat "$KSRC/.seagent-src" 2>/dev/null || true)" != "$LINUX_TARBALL_SHA" ]; then
		note "unpacking linux-$LINUX_VERSION"
		rm -rf -- "$KSRC" "$KOBJ"
		mkdir -p -- "$KSRC"
		tar -xJf "$LINUX_TARBALL" -C "$KSRC" --strip-components=1 --no-same-owner
		printf '%s\n' "$LINUX_TARBALL_SHA" >"$KSRC/.seagent-src"
	fi
fi

# Configure $KOBJ from allnoconfig + the fragments (+ extra lines on stdin), then
# check that every requested line made it into .config verbatim.
configure_kernel() {
	local frag="$OUT/build/kernel-$ARCH-$1.config"
	cat "$SCRIPT_DIR/kernel/common.config" "$SCRIPT_DIR/kernel/$KCONFIG_ARCH" - >"$frag"
	mkdir -p -- "$KOBJ"
	"${KMAKE[@]}" -C "$KSRC" O="$KOBJ" KCONFIG_ALLCONFIG="$frag" allnoconfig >"$OUT/build/kconfig-$1.log" 2>&1 ||
		{ tail -n 20 "$OUT/build/kconfig-$1.log" >&2; die "kernel configuration failed"; }
	local bad=0 line sym
	while IFS= read -r line; do
		case "$line" in
		CONFIG_*=*)
			grep -qxF -- "$line" "$KOBJ/.config" || {
				note "kernel config: wanted '$line', got '$(grep -E "^(# )?${line%%=*}[= ]" "$KOBJ/.config" || echo "<absent>")'"
				bad=1
			}
			;;
		"# CONFIG_"*" is not set")
			sym="${line#\# }"
			sym="${sym%% *}"
			! grep -q "^$sym=" "$KOBJ/.config" || {
				note "kernel config: wanted $sym off, got '$(grep "^$sym=" "$KOBJ/.config")'"
				bad=1
			}
			;;
		esac
	done <"$frag"
	[ "$bad" = 0 ] || die "the kernel config fragments do not apply to linux-$LINUX_VERSION (see above)"
	cp -f -- "$KOBJ/.config" "$OUT/build/kernel-$ARCH-$1.config.full"
}

# ── direct-boot kernel ────────────────────────────────────────────────────────
KERNEL_FORMAT="elf"
[ "$ARCH" = aarch64 ] && KERNEL_FORMAT="arm64-image"
case "$KERNEL_MODE" in
local)
	[ -f "$KERNEL" ] || die "--kernel $KERNEL does not exist"
	SHIPPED_SHA="$(sha256_of "$KERNEL")"
	if [ "$ARCH" = x86_64 ] && [ "$SHIPPED_SHA" != "$KERNEL_SHA256" ]; then
		note "WARNING: --kernel has sha256 $SHIPPED_SHA, not the pinned Firecracker CI $KERNEL_SHA256"
	fi
	KERNEL_SRC="$KERNEL"
	KERNEL_SOURCE_URL="local:$(basename "$KERNEL")"
	;;
firecracker)
	KERNEL_SRC="$DL/vmlinux"
	fetch "$KERNEL_URL" "$KERNEL_SHA256" "$KERNEL_SRC"
	KERNEL_SOURCE_URL="$KERNEL_URL"
	;;
source)
	note "building linux-$LINUX_VERSION for $ARCH (direct boot)"
	configure_kernel direct </dev/null
	if [ "$ARCH" = x86_64 ]; then
		"${KMAKE[@]}" -C "$KSRC" O="$KOBJ" vmlinux >"$OUT/build/kbuild-direct.log" 2>&1 ||
			{ tail -n 30 "$OUT/build/kbuild-direct.log" >&2; die "kernel build failed"; }
		KERNEL_SRC="$KOBJ/vmlinux"
	else
		"${KMAKE[@]}" -C "$KSRC" O="$KOBJ" Image >"$OUT/build/kbuild-direct.log" 2>&1 ||
			{ tail -n 30 "$OUT/build/kbuild-direct.log" >&2; die "kernel build failed"; }
		KERNEL_SRC="$KOBJ/arch/arm64/boot/Image"
	fi
	KERNEL_SOURCE_URL="$LINUX_URL"
	;;
esac
install -m 0644 -- "$KERNEL_SRC" "$KERNEL_OUT.part"
mv -f "$KERNEL_OUT.part" "$KERNEL_OUT"

# ── rootfs tarball ──────────────────────────────────────────────────────────
if [ -n "$ROOTFS" ]; then
	[ -f "$ROOTFS" ] || die "--rootfs $ROOTFS does not exist"
	ROOTFS_SHA="$(sha256_of "$ROOTFS")"
	[ "$ROOTFS_SHA" = "$ALPINE_SHA256" ] || note "WARNING: --rootfs sha256 is $ROOTFS_SHA, not the pinned $ALPINE_SHA256"
else
	ROOTFS="$DL/alpine-minirootfs-$ALPINE_VERSION-$ARCH.tar.gz"
	fetch "$ALPINE_URL" "$ALPINE_SHA256" "$ROOTFS"
	ROOTFS_SHA="$ALPINE_SHA256"
fi

# ── agent ───────────────────────────────────────────────────────────────────
build_agent() {
	local target="$1" flags="$2"
	note "building seagent-vm-guest for $target (release)"
	(
		cd "$REPO_ROOT"
		# Cross-building for aarch64 on an x86_64 host: link (and compile `ring`'s C)
		# with the cross gcc unless the caller configured something else.
		if [ "$ARCH" != "$HOST_ARCH" ] && command -v "$ARCH-linux-gnu-gcc" >/dev/null 2>&1; then
			local t="${target//-/_}" T
			T="$(printf '%s' "$t" | tr '[:lower:]' '[:upper:]')"
			eval ": \"\${CARGO_TARGET_${T}_LINKER:=$ARCH-linux-gnu-gcc}\"; export CARGO_TARGET_${T}_LINKER"
			eval ": \"\${CC_${t}:=$ARCH-linux-gnu-gcc}\"; export CC_${t}"
		fi
		CARGO_INCREMENTAL=0 RUSTFLAGS="$flags" "${CARGO:-cargo}" build -p seagent-vm --bin seagent-vm-guest --release --target "$target"
	)
}

if [ -z "$AGENT" ]; then
	command -v "${CARGO:-cargo}" >/dev/null 2>&1 || die "cargo not found; pass --agent PATH"
	if build_agent "$TARGET" ""; then
		:
	elif [ "$TARGET_EXPLICIT" = "0" ] && [ "$TARGET" = "$DEFAULT_TARGET" ]; then
		# The guest only needs a *static* binary; musl is the normal route, but a
		# musl C toolchain is not always installed (seagent-net pulls in `ring`, which
		# compiles C). Say so and use the GNU target with crt-static instead.
		note "WARNING: the musl build failed (a musl target needs musl-gcc, or clang with"
		note "         musl headers, in CC_${TARGET//-/_}). Falling back to a static GNU build;"
		note "         the guest gets the same statically linked binary, and the manifest"
		note "         records the target that was used."
		TARGET="$ARCH-unknown-linux-gnu"
		build_agent "$TARGET" "-C target-feature=+crt-static" ||
			die "agent build failed for both musl and a static GNU target"
	else
		die "agent build failed for $TARGET"
	fi
	AGENT="$REPO_ROOT/target/$TARGET/release/seagent-vm-guest"
fi
[ "$AGENT_CHECKED" = 1 ] || check_agent
AGENT_SHA="$(sha256_of "$AGENT")"
AGENT_VERSION="unknown"
if [ "$ARCH" = "$HOST_ARCH" ]; then
	AGENT_VERSION="$("$AGENT" version 2>/dev/null || echo unknown)"
fi

# ── unpack, install the agent, pack ─────────────────────────────────────────
note "unpacking the Alpine rootfs into $ROOT"
rm -rf -- "$ROOT"
mkdir -p -- "$ROOT"
# --no-same-owner: we are not root. Device nodes in the tarball are skipped (the
# guest mounts devtmpfs over /dev anyway).
if ! tar -xzf "$ROOTFS" -C "$ROOT" --no-same-owner --numeric-owner 2>"$OUT/build/tar.err"; then
	note "tar reported problems (expected without root for /dev nodes):"
	sed -n '1,5p' "$OUT/build/tar.err" >&2
fi
[ -x "$ROOT/bin/busybox" ] || die "the rootfs does not look like Alpine (no /bin/busybox)"

mkdir -p -- "$ROOT/sbin" "$ROOT/usr/bin" "$ROOT/home/agent" "$ROOT/run" "$ROOT/tmp"
chmod 0755 -- "$ROOT/home/agent" "$ROOT/run" "$ROOT/tmp"
# /sbin/init is a symlink to busybox in Alpine: replace it, do not write through.
rm -f -- "$ROOT/sbin/init"
install -m 0755 -- "$AGENT" "$ROOT/sbin/init"
install -m 0755 -- "$AGENT" "$ROOT/usr/bin/seagent-vm-guest"
ln -sfn seagent-vm-guest "$ROOT/usr/bin/seagent-broker"

# The one non-root account. The agent drops to this uid; nothing else exists.
if ! grep -q '^agent:' "$ROOT/etc/passwd"; then
	printf 'agent:x:1000:1000:seagent agent:/home/agent:/bin/sh\n' >>"$ROOT/etc/passwd"
fi
if ! grep -q '^agent:' "$ROOT/etc/group"; then
	printf 'agent:x:1000:\n' >>"$ROOT/etc/group"
fi

note "packing the initramfs"
# `--owner 0:0` is not cosmetic: the rootfs is unpacked as the *build* user, so
# without it every file in the guest would be owned by that uid — the agent's
# uid 1000 included, which would make /etc/passwd writable from inside the VM.
# The guest must own nothing but its own workspace and home (B2).
(
	cd "$ROOT"
	find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc --quiet --owner 0:0 | gzip -1 -n
) >"$INITRAMFS_OUT.part"
mv -f "$INITRAMFS_OUT.part" "$INITRAMFS_OUT"

# ── disk: EFI-stub kernel with the initramfs and command line built in ──────
DISK_JSON=""
if [ "$FORMAT" = disk ]; then
	note "building linux-$LINUX_VERSION for $ARCH (EFI disk: initramfs + cmdline built in)"
	# The kernel takes a `.cpio.gz` as INITRAMFS_SOURCE as-is (no re-compression),
	# so the disk embeds byte-for-byte the archive that is also shipped separately —
	# followed by one more tiny gzip member holding /dev/console.
	# Direct boot gets that node from the kernel's *default* built-in archive
	# (usr/default_cpio_list), unpacked before the external initrd; a configured
	# INITRAMFS_SOURCE replaces that default, and without /dev/console PID 1 starts
	# with fds 0-2 closed: Rust's runtime then cannot open /dev/null, aborts, and the
	# kernel panics with "Attempted to kill init! exitcode=0x0000000b". Only the
	# console, exactly like the default list: the agent mounts devtmpfs only when
	# /dev/null is absent, so shipping /dev/null would hide /dev/ttyS1 (the channel).
	# The node is written by the kernel's own gen_init_cpio (no root, no mknod); the
	# kernel's unpacker reads concatenated archives, each compressed on its own.
	DISK_INITRAMFS="$OUT/build/initramfs-disk.cpio.gz"
	printf 'dir /dev 0755 0 0\nnod /dev/console 0600 0 0 c 5 1\n' >"$OUT/build/dev-nodes.list"
	"${HOSTCC:-cc}" -O2 -o "$OUT/build/gen_init_cpio" "$KSRC/usr/gen_init_cpio.c" ||
		die "cannot build the kernel's usr/gen_init_cpio with ${HOSTCC:-cc}"
	{
		cat -- "$INITRAMFS_OUT"
		"$OUT/build/gen_init_cpio" -t 0 "$OUT/build/dev-nodes.list" | gzip -1 -n
	} >"$DISK_INITRAMFS"
	{
		printf 'CONFIG_INITRAMFS_SOURCE="%s"\n' "$DISK_INITRAMFS"
		if [ "$ARCH" = x86_64 ]; then
			printf 'CONFIG_CMDLINE_BOOL=y\nCONFIG_CMDLINE="%s"\nCONFIG_CMDLINE_OVERRIDE=y\n' "$DISK_CMDLINE"
		else
			printf 'CONFIG_CMDLINE="%s"\nCONFIG_CMDLINE_FORCE=y\n' "$DISK_CMDLINE"
		fi
	} | configure_kernel disk
	if [ "$ARCH" = x86_64 ]; then
		"${KMAKE[@]}" -C "$KSRC" O="$KOBJ" bzImage >"$OUT/build/kbuild-disk.log" 2>&1 ||
			{ tail -n 30 "$OUT/build/kbuild-disk.log" >&2; die "kernel build failed"; }
		EFI_SRC="$KOBJ/arch/x86/boot/bzImage"
	else
		"${KMAKE[@]}" -C "$KSRC" O="$KOBJ" Image >"$OUT/build/kbuild-disk.log" 2>&1 ||
			{ tail -n 30 "$OUT/build/kbuild-disk.log" >&2; die "kernel build failed"; }
		EFI_SRC="$KOBJ/arch/arm64/boot/Image"
	fi
	# Both are PE/COFF images ("MZ" + PE header): what the firmware loads.
	[ "$(head -c 2 "$EFI_SRC")" = "MZ" ] || die "$EFI_SRC is not an EFI application (no MZ header); is CONFIG_EFI_STUB on?"
	install -m 0644 -- "$EFI_SRC" "$OUT/build/$EFI_NAME"
	"$PYTHON" -I "$SCRIPT_DIR/mkdisk.py" write --out "$DISK_OUT" --esp-mib "$ESP_MIB" \
		--file "EFI/BOOT/$EFI_NAME=$OUT/build/$EFI_NAME" >"$OUT/build/mkdisk.out"
	"$PYTHON" -I "$SCRIPT_DIR/mkdisk.py" verify "$DISK_OUT" --file "EFI/BOOT/$EFI_NAME=$OUT/build/$EFI_NAME" >/dev/null ||
		die "disk.raw failed its read-back check"
	# A converted disk.vdi / disk.vhdx next to an older disk.raw would be booted
	# instead of the new one (the providers convert only when it is missing).
	rm -f -- "$OUT/disk.vdi" "$OUT/disk.vhdx"
	DISK_JSON=$(
		cat <<EOF
,
  "disk": {
    "path": "disk.raw",
    "sha256": "$(sha256_of "$DISK_OUT")",
    "size": $(stat -c%s "$DISK_OUT"),
    "layout": "gpt+fat32-esp",
    "efi_binary": "EFI/BOOT/$EFI_NAME",
    "efi_sha256": "$(sha256_of "$OUT/build/$EFI_NAME")",
    "cmdline": "$DISK_CMDLINE",
    "channel": "uart"
  }
EOF
	)
fi

# ── manifest ────────────────────────────────────────────────────────────────
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"; }
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	BUILT_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
else
	BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi
KERNEL_EXTRA=""
if [ "$NEED_KERNEL_TREE" = 1 ]; then
	KERNEL_EXTRA=",
    \"linux\": {\"version\": \"$LINUX_VERSION\", \"url\": $(json_str "$LINUX_URL"), \"sha256\": \"$LINUX_TARBALL_SHA\"}"
fi
cat >"$OUT/manifest.json.part" <<EOF
{
  "image_version": 1,
  "arch": "$ARCH",
  "built_at": $(json_str "$BUILT_AT"),
  "kernel": {
    "path": "vmlinux",
    "sha256": "$(sha256_of "$KERNEL_OUT")",
    "size": $(stat -c%s "$KERNEL_OUT"),
    "format": "$KERNEL_FORMAT",
    "source_url": $(json_str "$KERNEL_SOURCE_URL")$KERNEL_EXTRA
  },
  "initramfs": {
    "path": "initramfs.cpio.gz",
    "sha256": "$(sha256_of "$INITRAMFS_OUT")",
    "size": $(stat -c%s "$INITRAMFS_OUT")
  },
  "agent": {
    "sha256": "$AGENT_SHA",
    "version": $(json_str "$AGENT_VERSION"),
    "target": $(json_str "$TARGET"),
    "init": "/sbin/init"
  },
  "alpine": {
    "version": $(json_str "$ALPINE_VERSION"),
    "url": $(json_str "$ALPINE_URL"),
    "sha256": "$ROOTFS_SHA"
  }$DISK_JSON
}
EOF
mv -f "$OUT/manifest.json.part" "$OUT/manifest.json"

note "arch $ARCH, format $FORMAT"
note "kernel sha256    $(sha256_of "$KERNEL_OUT") ($(stat -c%s "$KERNEL_OUT") bytes, $KERNEL_FORMAT)"
note "initramfs sha256 $(sha256_of "$INITRAMFS_OUT") ($(stat -c%s "$INITRAMFS_OUT") bytes)"
[ "$FORMAT" = disk ] && note "disk.raw sha256  $(sha256_of "$DISK_OUT") ($(stat -c%s "$DISK_OUT") bytes, ESP \\EFI\\BOOT\\$EFI_NAME)"
note "agent: $AGENT_VERSION  sha256 $AGENT_SHA"
printf '%s\n%s\n' "$KERNEL_OUT" "$INITRAMFS_OUT"
[ "$FORMAT" = disk ] && printf '%s\n' "$DISK_OUT"
exit 0
