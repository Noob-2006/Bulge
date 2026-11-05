#!/usr/bin/env bash
# Build the seagent microVM guest image: one kernel + one read-only initramfs that
# has the guest agent (`seagent-vm-guest`) as `/sbin/init`.
#
# Everything the VM needs is in these two files: the guest root is an initramfs
# mounted by the kernel, so there is no disk, no host directory and no bind
# mount inside the VM (B2). `seagent.workspace_ro=1` and the agent's privilege drop
# are enforced by the guest, on top of that.
#
# The script is idempotent, needs no root and never touches anything outside
# `--out DIR`: downloads land in `DIR/dl`, the unpacked rootfs in `DIR/build`,
# the two artefacts in `DIR`. Re-running with the artefacts in place skips the
# download (after a sha256 check) and rebuilds the initramfs from scratch, so a
# second run with `--agent` is the offline workflow.
#
# Usage: packaging/vm/build-image.sh [--out DIR] [--agent PATH] [--kernel PATH]
#                                    [--rootfs PATH] [--target TRIPLE] [--help]
set -euo pipefail

KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223"
# Firecracker CI 5.10.223: built for virtio-mmio (Firecracker) and, importantly,
# with virtio and devtmpfs built in — no modules, so nothing has to be loaded
# from inside an unprivileged guest.
KERNEL_SHA256="22847375721aceea63d934c28f2dfce4670b6f52ec904fae19f5145a970c1e65"
ALPINE_VERSION="3.20.3"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz"
ALPINE_SHA256="d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c"
DEFAULT_TARGET="x86_64-unknown-linux-musl"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

usage() {
	cat <<'EOF'
seagent microVM guest image builder

  build-image.sh [options]

Builds a kernel + initramfs pair that boots into the seagent guest agent
(`seagent-vm-guest` installed as /sbin/init). No root, no sudo, no writes outside
--out.

Options:
  --out DIR        Where to put the artefacts (default: $TMPDIR/seagent-vm-image).
                   Contains: vmlinux, initramfs.cpio.gz, manifest.json, and the
                   dl/ download cache + build/ unpacked rootfs.
  --agent PATH     Use this prebuilt seagent-vm-guest instead of building it
                   (the offline path, and how tests inject a known binary).
  --kernel PATH    Use this kernel file instead of downloading it. A local copy
                   is never fetched again, so the image can be rebuilt offline.
  --rootfs PATH    Use this Alpine minirootfs tarball instead of downloading it.
  --target TRIPLE  Rust target for the agent (default: x86_64-unknown-linux-musl;
                   the binary must be static to run inside the guest).
  --help, -h       This text.

Environment:
  TMPDIR           Default --out lives under it.
  CARGO            Cargo binary to use (default: cargo).
  CC_<triple>      Passed through to cargo; a musl target needs a C compiler for
                   the musl libc (musl-gcc, or clang with musl headers).

Output: prints the absolute paths of the kernel and the initramfs, then exits 0.
The image is self-contained: `vmlinux` + `initramfs.cpio.gz` + `manifest.json`
are all a provider needs, and they stay valid with the network turned off.

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
ROOTFS=""
TARGET="${AGENT_TARGET:-$DEFAULT_TARGET}"
TARGET_EXPLICIT=0

while [ $# -gt 0 ]; do
	case "$1" in
	--out)
		[ $# -ge 2 ] || die "--out needs a directory"
		OUT="$2"
		shift 2
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

if [ -z "$OUT" ]; then
	: "${TMPDIR:=$HOME/.cache}"
	OUT="$TMPDIR/seagent-vm-image"
fi
mkdir -p "$OUT/dl" "$OUT/build"
OUT="$(cd -- "$OUT" && pwd)"
DL="$OUT/dl"
ROOT="$OUT/build/root"
KERNEL_OUT="$OUT/vmlinux"
INITRAMFS_OUT="$OUT/initramfs.cpio.gz"

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

# ── kernel ──────────────────────────────────────────────────────────────────
if [ -n "$KERNEL" ]; then
	[ -f "$KERNEL" ] || die "--kernel $KERNEL does not exist"
	SHIPPED_SHA="$(sha256_of "$KERNEL")"
	if [ "$SHIPPED_SHA" != "$KERNEL_SHA256" ]; then
		note "WARNING: --kernel has sha256 $SHIPPED_SHA, not the pinned $KERNEL_SHA256"
	fi
	KERNEL_SRC="$KERNEL"
else
	KERNEL_SRC="$DL/vmlinux"
	fetch "$KERNEL_URL" "$KERNEL_SHA256" "$KERNEL_SRC"
	SHIPPED_SHA="$KERNEL_SHA256"
fi
install -m 0644 -- "$KERNEL_SRC" "$KERNEL_OUT"

# ── rootfs tarball ──────────────────────────────────────────────────────────
if [ -n "$ROOTFS" ]; then
	[ -f "$ROOTFS" ] || die "--rootfs $ROOTFS does not exist"
	ROOTFS_SHA="$(sha256_of "$ROOTFS")"
	[ "$ROOTFS_SHA" = "$ALPINE_SHA256" ] || note "WARNING: --rootfs sha256 is $ROOTFS_SHA, not the pinned $ALPINE_SHA256"
else
	ROOTFS="$DL/alpine-minirootfs-$ALPINE_VERSION-x86_64.tar.gz"
	fetch "$ALPINE_URL" "$ALPINE_SHA256" "$ROOTFS"
	ROOTFS_SHA="$ALPINE_SHA256"
fi

# ── agent ───────────────────────────────────────────────────────────────────
build_agent() {
	local target="$1" flags="$2"
	note "building seagent-vm-guest for $target (release)"
	(
		cd "$REPO_ROOT"
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
		TARGET="x86_64-unknown-linux-gnu"
		build_agent "$TARGET" "-C target-feature=+crt-static" ||
			die "agent build failed for both musl and a static GNU target"
	else
		die "agent build failed for $TARGET"
	fi
	AGENT="$REPO_ROOT/target/$TARGET/release/seagent-vm-guest"
fi
[ -f "$AGENT" ] || die "--agent $AGENT does not exist"
case "$(file -b "$AGENT" 2>/dev/null || true)" in
*"statically linked"* | *"static-pie"*) ;;
*) note "WARNING: $AGENT does not look statically linked; the guest has no dynamic loader" ;;
esac
AGENT_SHA="$(sha256_of "$AGENT")"
AGENT_VERSION="$("$AGENT" version 2>/dev/null || echo unknown)"

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
	find . -print0 | cpio --null -o -H newc --quiet --owner 0:0 | gzip -1
) >"$INITRAMFS_OUT.part"
mv -f "$INITRAMFS_OUT.part" "$INITRAMFS_OUT"

# ── manifest ────────────────────────────────────────────────────────────────
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"; }
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat >"$OUT/manifest.json" <<EOF
{
  "image_version": 1,
  "built_at": $(json_str "$BUILT_AT"),
  "kernel": {
    "path": "vmlinux",
    "sha256": "$(sha256_of "$KERNEL_OUT")",
    "size": $(stat -c%s "$KERNEL_OUT"),
    "source_url": $(json_str "$KERNEL_URL")
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
  }
}
EOF

note "kernel sha256    $(sha256_of "$KERNEL_OUT") ($(stat -c%s "$KERNEL_OUT") bytes)"
note "initramfs sha256 $(sha256_of "$INITRAMFS_OUT") ($(stat -c%s "$INITRAMFS_OUT") bytes)"
note "agent: $AGENT_VERSION  sha256 $AGENT_SHA"
printf '%s\n%s\n' "$KERNEL_OUT" "$INITRAMFS_OUT"
