#!/usr/bin/env bash
# Stage the built-in VM that the desktop installers ship (apps/desktop/src-tauri/vm → the app's
# resources `vm/`, read by crates/seagent-vm/src/bundle.rs): the guest image built by
# build-image.sh plus the hypervisor front-end of the target OS, each pinned by hash.
#
#   packaging/vm/bundle.sh --os windows --image "$IMG" [--out DIR] [--cache DIR]
#   packaging/vm/bundle.sh --os linux   --image "$IMG"
#   packaging/vm/bundle.sh --os macos   --arch aarch64 --image "$IMG_ARM64"
#
#   --os OS        windows | macos | linux (the installer's OS)
#   --arch ARCH    x86_64 (default) | aarch64: the guest = host CPU
#   --image DIR    a build-image.sh output (vmlinux, initramfs.cpio.gz, manifest.json); for
#                  Windows it must be a --build-kernel image (QEMU needs the virtio-PCI kernel)
#   --out DIR      default apps/desktop/src-tauri/vm (replaced)
#   --cache DIR    downloads (default $TMPDIR/seagent-vm-bundle-cache); re-used when the hash matches
#   --lock FILE    compare the image's manifest sha256 with the reference in FILE
#                  (packaging/vm/image.lock) and say whether this build reproduced it
#
# Runtimes (downloaded from their upstream release, checked against the hash pinned here; a
# mismatch is never accepted):
#   windows  QEMU for Windows (Stefan Weil's build, the one qemu.org links to), trimmed to
#            qemu-system-x86_64.exe, the DLLs it imports and four firmware files
#            (packaging/vm/qemu-windows-files.txt); 7-Zip unpacks the NSIS installer
#   macos    vfkit (Apple Virtualization.framework CLI), universal binary
#   linux    Firecracker, the static release binary (KVM; no QEMU package needed)
#
# Prints, last, `SEAGENT_VM_IMAGE_MANIFEST_SHA256=<sha256>`: export it while building the
# seagent sidecar so the installed agent accepts exactly this image (bundle::PINNED_MANIFEST_SHA256).
# Needs: bash, curl, sha256sum (or shasum), tar, python3 (or python, or PYTHON=path); Windows
# bundles also 7z/7zz/7za. Runs on Linux, macOS and Git Bash on Windows (the CI runners).
set -euo pipefail
umask 022

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

QEMU_URL="https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.exe"
QEMU_SHA512="5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543"
QEMU_VERSION="QEMU 11.1.0 (v11.1.0-12130-ge470268ff4), qemu-w64-setup-20260811"
QEMU_SOURCE="https://gitlab.com/qemu-project/qemu/-/tree/e470268ff4 (QEMU, GPL-2.0-only); the DLLs are MSYS2 mingw-w64 packages, sources at https://github.com/msys2/MINGW-packages"
VFKIT_URL="https://github.com/crc-org/vfkit/releases/download/v0.6.4/vfkit"
VFKIT_SHA256="0ed83fc8ca7aa708598835480dba1362406aa7cd1dab3b27464eb76327d9652d"
VFKIT_LICENSE_URL="https://raw.githubusercontent.com/crc-org/vfkit/v0.6.4/LICENSE"
VFKIT_LICENSE_SHA256="5f5e4630cc08816eca34d970ec6d3420f752f399bbcc4badab5b3435c1807e6b"
FC_VERSION="v1.18.0"
FC_SHA256_x86_64="1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd"
FC_SHA256_aarch64="2a6130ff0338901ff9d7fbd73ce046c6b1c6123889dc84a34d678aa53bd0c0c2"

die() { printf 'bundle: %s\n' "$*" >&2; exit 1; }
note() { printf 'bundle: %s\n' "$*" >&2; }

OS="" ARCH="x86_64" IMAGE="" OUT="$root/apps/desktop/src-tauri/vm" CACHE="" LOCK=""
while [ $# -gt 0 ]; do
	case "$1" in
	--os) OS="${2:?}"; shift 2 ;;
	--arch) ARCH="${2:?}"; shift 2 ;;
	--image) IMAGE="${2:?}"; shift 2 ;;
	--out) OUT="${2:?}"; shift 2 ;;
	--cache) CACHE="${2:?}"; shift 2 ;;
	--lock) LOCK="${2:?}"; shift 2 ;;
	-h | --help) sed -n '2,32p' "$0"; exit 0 ;;
	*) die "unknown option '$1' (see --help)" ;;
	esac
done
case "$OS" in windows | macos | linux) ;; *) die "--os windows|macos|linux" ;; esac
case "$ARCH" in x86_64 | aarch64) ;; *) die "--arch x86_64|aarch64" ;; esac
[ -f "$IMAGE/manifest.json" ] || die "--image $IMAGE has no manifest.json (build it with packaging/vm/build-image.sh)"
[ "$OS" = windows ] && [ "$ARCH" != x86_64 ] && die "the Windows bundle is x86_64 only (no arm64 QEMU+WHPX build is pinned)"
: "${CACHE:=${TMPDIR:-/tmp}/seagent-vm-bundle-cache}"
mkdir -p "$CACHE"

# The first Python that really runs: on Windows runners `python3` can be the Microsoft Store
# alias, which exists on PATH but only prints an install hint.
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
	for c in python3 python py; do command -v "$c" >/dev/null && "$c" -c "import sys" >/dev/null 2>&1 && { PY="$c"; break; }; done
fi
[ -n "$PY" ] || die "python3 is required"

sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
sha512_of() { if command -v sha512sum >/dev/null; then sha512sum "$1" | cut -d' ' -f1; else shasum -a 512 "$1" | cut -d' ' -f1; fi; }

# fetch URL ALGO HASH DEST: download unless DEST already has the hash; never accept a mismatch.
fetch() {
	local url="$1" algo="$2" want="$3" dest="$4" got
	if [ -f "$dest" ] && [ "$("${algo}_of" "$dest")" = "$want" ]; then
		note "$(basename "$dest") cached ($algo ok)"
		return 0
	fi
	note "downloading $url"
	curl -fsSL --retry 3 --connect-timeout 30 -o "$dest.part" "$url" || die "download failed: $url"
	got="$("${algo}_of" "$dest.part")"
	[ "$got" = "$want" ] || { rm -f "$dest.part"; die "$algo mismatch for $url: expected $want, got $got"; }
	mv -f "$dest.part" "$dest"
}

# The image: the three files the manifest pins, copied as they are.
"$PY" -I - "$IMAGE/manifest.json" "$ARCH" <<'PY' || die "the image does not fit this bundle (see above)"
import json, sys
m = json.load(open(sys.argv[1]))
if m.get("image_version") != 1:
    sys.exit(f"bundle: image_version {m.get('image_version')} (the agent speaks 1)")
if m.get("arch", "x86_64") != sys.argv[2]:
    sys.exit(f"bundle: the image is {m.get('arch')}, the bundle is {sys.argv[2]}")
if sys.argv[2] == "x86_64" and "linux" not in m["kernel"]:
    sys.exit("bundle: the x86_64 image must be built with --build-kernel (the Firecracker CI kernel has no PCI, so QEMU's channel never appears)")
PY
rm -rf -- "$OUT"
img_out="$OUT/image/$ARCH"
mkdir -p "$img_out" "$OUT/LICENSES"
for f in vmlinux initramfs.cpio.gz manifest.json; do
	install -m 0644 "$IMAGE/$f" "$img_out/$f"
done
"$PY" -I - "$img_out" <<'PY' || die "the copied image does not verify"
import hashlib, json, os, sys
d = sys.argv[1]
m = json.load(open(os.path.join(d, "manifest.json")))
for k in ("kernel", "initramfs"):
    p = os.path.join(d, m[k]["path"])
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    if h != m[k]["sha256"] or os.path.getsize(p) != m[k]["size"]:
        sys.exit(f"bundle: {p} does not match its manifest")
PY
MANIFEST_SHA="$(sha256_of "$img_out/manifest.json")"

# ── runtime ──────────────────────────────────────────────────────────────────
declare -a FILES=()
case "$OS" in
windows)
	KIND=qemu EXE=qemu-system-x86_64.exe VERSION="$QEMU_VERSION" LICENSE="GPL-2.0-only" SRC="$QEMU_URL" SRC_SHA="sha512:$QEMU_SHA512" SRC_CODE="$QEMU_SOURCE"
	setup="$CACHE/$(basename "$QEMU_URL")"
	fetch "$QEMU_URL" sha512 "$QEMU_SHA512" "$setup"
	sz="${SEVENZIP:-}"
	[ -n "$sz" ] || for c in 7z 7zz 7za; do command -v "$c" >/dev/null && { sz="$c"; break; }; done
	[ -n "$sz" ] || die "7-Zip (7z / 7zz / 7za, or SEVENZIP=path) is needed to unpack the QEMU installer"
	x="$CACHE/qemu-x"
	if [ ! -f "$x/.from" ] || [ "$(cat "$x/.from")" != "$QEMU_SHA512" ]; then
		rm -rf -- "$x"
		"$sz" x -y -o"$x" "$setup" >/dev/null || die "7-Zip could not unpack $setup"
		printf '%s\n' "$QEMU_SHA512" >"$x/.from"
	fi
	rt="$OUT/runtime/qemu"
	mkdir -p "$rt/share"
	while IFS= read -r f; do
		case "$f" in '' | '#'*) continue ;; esac
		[ -f "$x/$f" ] || die "the pinned QEMU build has no $f (packaging/vm/qemu-windows-files.txt is out of date)"
		install -m 0644 "$x/$f" "$rt/$f"
		FILES+=("$f")
	done <"$here/qemu-windows-files.txt"
	# Every DLL the emulator imports must be there (the Windows loader refuses to start it
	# otherwise); checked whenever a PE-aware objdump is around.
	od=""
	for c in x86_64-w64-mingw32-objdump objdump; do command -v "$c" >/dev/null && "$c" -p "$rt/$EXE" >/dev/null 2>&1 && { od="$c"; break; }; done
	if [ -n "$od" ]; then
		for f in "$rt"/*.exe "$rt"/*.dll; do
			for d in $("$od" -p "$f" | awk '/DLL Name:/ {print $3}'); do
				[ -f "$x/$d" ] && [ ! -f "$rt/$d" ] && die "$(basename "$f") imports $d, which is not in qemu-windows-files.txt"
			done
		done
		note "DLL closure of $EXE checked with $od"
	else
		note "no PE objdump: the DLL closure was not re-checked (the pinned list is used as is)"
	fi
	install -m 0644 "$x/COPYING" "$OUT/LICENSES/QEMU-COPYING.txt"
	install -m 0644 "$x/COPYING.LIB" "$OUT/LICENSES/QEMU-COPYING.LIB.txt"
	;;
macos)
	KIND=vfkit EXE=vfkit VERSION="vfkit v0.6.4" LICENSE="Apache-2.0" SRC="$VFKIT_URL" SRC_SHA="sha256:$VFKIT_SHA256" SRC_CODE="https://github.com/crc-org/vfkit/tree/v0.6.4"
	rt="$OUT/runtime/vfkit"
	mkdir -p "$rt"
	fetch "$VFKIT_URL" sha256 "$VFKIT_SHA256" "$CACHE/vfkit-v0.6.4"
	fetch "$VFKIT_LICENSE_URL" sha256 "$VFKIT_LICENSE_SHA256" "$CACHE/vfkit-LICENSE"
	install -m 0755 "$CACHE/vfkit-v0.6.4" "$rt/vfkit"
	install -m 0644 "$CACHE/vfkit-LICENSE" "$OUT/LICENSES/vfkit-LICENSE.txt"
	FILES=(vfkit)
	;;
linux)
	KIND=firecracker EXE=firecracker VERSION="Firecracker $FC_VERSION" LICENSE="Apache-2.0" SRC_CODE="https://github.com/firecracker-microvm/firecracker/tree/$FC_VERSION"
	SRC="https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz"
	want="FC_SHA256_$ARCH"
	SRC_SHA="sha256:${!want}"
	tgz="$CACHE/$(basename "$SRC")"
	fetch "$SRC" sha256 "${!want}" "$tgz"
	rt="$OUT/runtime/firecracker"
	mkdir -p "$rt"
	rel="release-$FC_VERSION-$ARCH"
	tar -xzf "$tgz" -C "$CACHE" "$rel/firecracker-$FC_VERSION-$ARCH" "$rel/LICENSE" "$rel/NOTICE" "$rel/THIRD-PARTY"
	install -m 0755 "$CACHE/$rel/firecracker-$FC_VERSION-$ARCH" "$rt/firecracker"
	install -m 0644 "$CACHE/$rel/LICENSE" "$OUT/LICENSES/Firecracker-LICENSE.txt"
	install -m 0644 "$CACHE/$rel/NOTICE" "$OUT/LICENSES/Firecracker-NOTICE.txt"
	install -m 0644 "$CACHE/$rel/THIRD-PARTY" "$OUT/LICENSES/Firecracker-THIRD-PARTY.txt"
	FILES=(firecracker)
	;;
esac

# The guest itself is GPL software too (Linux, BusyBox): say where its exact sources are.
"$PY" -I - "$img_out/manifest.json" "$OUT/LICENSES/SOURCES.txt" "$KIND" "$VERSION" "$LICENSE" "$SRC" "$SRC_CODE" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
kind, version, lic, src, code = sys.argv[3:8]
linux = m["kernel"].get("linux", {})
lines = [
    "SE Agent built-in VM: third-party software and where its source code is",
    "",
    f"{kind}: {version} — licence {lic}",
    f"  binary from  {src}",
    f"  source code  {code}",
    "",
    f"Linux kernel {linux.get('version', '?')} (guest kernel, GPL-2.0-only)",
    f"  source code  {linux.get('url', m['kernel'].get('source_url', '?'))}  sha256 {linux.get('sha256', '?')}",
    "  configuration: packaging/vm/kernel/*.config in the SE Agent source tree",
    "",
    f"Alpine Linux minirootfs {m['alpine']['version']} (guest userland: BusyBox GPL-2.0-only, musl MIT, …)",
    f"  binary from  {m['alpine']['url']}  sha256 {m['alpine']['sha256']}",
    f"  source code  https://gitlab.alpinelinux.org/alpine/aports/-/tree/v{m['alpine']['version']} and the package sources it names",
    "",
    "Written offer: for three years from the date you received this program, the SE Agent",
    "contributors will provide the complete corresponding source code of the GPL-licensed",
    "components above on request (https://github.com/Noob-2006/System-Engineering-Agent/issues).",
]
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
PY

# bundle.json, with the sha256 of every runtime file (the app's "repair" re-checks them).
"$PY" -I - "$OUT" "$OS" "$ARCH" "$MANIFEST_SHA" "$KIND" "$EXE" "$VERSION" "$LICENSE" "$SRC" "$SRC_SHA" "$SRC_CODE" "${FILES[@]}" <<'PY'
import hashlib, json, os, sys
out, os_, arch, msha, kind, exe, version, lic, src, srcsha, code, *files = sys.argv[1:]
rt = f"runtime/{kind}"
info = {
    "bundle_version": 1, "os": os_, "arch": arch,
    "image": {"dir": f"image/{arch}", "manifest_sha256": msha},
    "runtime": {"kind": kind, "dir": rt, "exe": exe, "version": version, "license": lic, "source": src, "source_sha": srcsha, "source_code": code,
                "files": {f: hashlib.sha256(open(os.path.join(out, rt, f), "rb").read()).hexdigest() for f in sorted(files)}},
}
json.dump(info, open(os.path.join(out, "bundle.json"), "w"), indent=2, sort_keys=True)
PY

if [ -n "$LOCK" ]; then
	ref="$("$PY" -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["reference"].get(sys.argv[2], {}).get("manifest_sha256", ""))' "$LOCK" "$ARCH")"
	if [ "$ref" = "$MANIFEST_SHA" ]; then
		note "the image reproduces the reference build in $(basename "$LOCK") (manifest $MANIFEST_SHA)"
	else
		note "NOTE: manifest $MANIFEST_SHA differs from the reference in $(basename "$LOCK") (${ref:-none}): another toolchain or other sources; the installer pins the image it actually ships"
	fi
fi

total="$(du -sk "$OUT" | cut -f1)"
note "staged $OS/$ARCH bundle in $OUT (${total} KiB): $KIND ${#FILES[@]} files, image manifest $MANIFEST_SHA"
printf 'SEAGENT_VM_IMAGE_MANIFEST_SHA256=%s\n' "$MANIFEST_SHA"
