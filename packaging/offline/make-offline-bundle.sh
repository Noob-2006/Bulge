#!/usr/bin/env bash
# Air-gapped install bundle (ent-029): one tarball that carries everything and needs no network.
#
#   make-offline-bundle.sh --dist DIST_DIR --arch x86_64|aarch64 --out ark-offline-<ver>-<arch>.tar.gz
#                          [--vm-image DIR] [--key release-key.pem] [--with-browser [--browser-zip FILE]]
#
# DIST_DIR is a verified release directory (verify-release.sh passes on it): ark-<triple>.tar.gz,
# optional *.deb/*.rpm, sbom.spdx.json, SHA256SUMS, SHA256SUMS.sig, release-key.pub.pem.
# Bundle layout (top directory ark-offline/):
#   release/        the dist directory, byte for byte (its own signature still verifies)
#   vm-image/       optional microVM guest image (`ark sandbox vm image build` output: vmlinux, initramfs, manifest)
#   browser/        with --with-browser: the pinned Chrome for Testing chrome-linux64.zip (sha256
#                   checked here and again by install.sh --with-browser / install-offline.sh)
#   tools/          verify-release.sh, sbom.py, install-offline.sh helpers
#   install-offline.sh   the installer (verifies everything, then installs; no network, no sudo of its own)
#   BUNDLE.sha256   hashes of everything outside release/ (+ BUNDLE.sha256.sig when --key is given)
set -euo pipefail
export LC_ALL=C
PROG=$(basename "$0")
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
DIST="" ARCH="" OUT="" VMIMG="" KEY="" BROWSER=0 BROWSER_ZIP=""
# Pinned Chrome for Testing (same values as packaging/install.sh and ark_browser::launch).
CFT_VERSION=157.0.8103.38
CFT_SHA256=8cdeb344e9b2cefe59f4aea8d1d93d5d93054c03cde217665c16fc1f62e72a66
while [ $# -gt 0 ]; do
    case "$1" in
        --with-browser) BROWSER=1 ;;
        --browser-zip) BROWSER_ZIP=${2:?}; BROWSER=1; shift ;;
        --dist) DIST=${2:?}; shift ;;
        --arch) ARCH=${2:?}; shift ;;
        --out) OUT=${2:?}; shift ;;
        --vm-image) VMIMG=${2:?}; shift ;;
        --key) KEY=${2:?}; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
    shift
done
[ -d "$DIST" ] && [ -n "$OUT" ] || die "usage: $PROG --dist DIR --arch ARCH --out FILE"
case "$ARCH" in x86_64|aarch64) ;; *) die "--arch must be x86_64 or aarch64" ;; esac
[ -f "$DIST/ark-$ARCH-unknown-linux-musl.tar.gz" ] || die "$DIST/ark-$ARCH-unknown-linux-musl.tar.gz is missing"
# Never bundle something that does not verify: the installer would refuse it on the far side anyway.
if [ -f "$DIST/SHA256SUMS.sig" ]; then
    "$ROOT/packaging/release/verify-release.sh" "$DIST" --key "${ARK_RELEASE_PUBKEY:-$DIST/release-key.pub.pem}" >/dev/null || die "the release directory does not verify"
fi
if [ -n "$VMIMG" ]; then
    [ -f "$VMIMG/manifest.json" ] || die "--vm-image: no manifest.json in $VMIMG"
fi
EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/ark-offline.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
B=$STAGE/ark-offline
mkdir -p "$B/release" "$B/tools"
cp -R "$DIST/." "$B/release/"
install -m 0755 "$ROOT/packaging/release/verify-release.sh" "$B/tools/verify-release.sh"
install -m 0755 "$ROOT/packaging/release/sbom.py" "$B/tools/sbom.py"
install -m 0755 "$HERE/install-offline.sh" "$B/install-offline.sh"
# the one-command installer: run from the bundle it installs release/ without any network
install -m 0755 "$HERE/../install.sh" "$B/install.sh"
if [ -n "$VMIMG" ]; then mkdir -p "$B/vm-image"; cp -R "$VMIMG/." "$B/vm-image/"; fi
if [ "$BROWSER" = 1 ]; then
    [ "$ARCH" = x86_64 ] || die "--with-browser: Chrome for Testing has no linux $ARCH build"
    mkdir -p "$B/browser"
    if [ -n "$BROWSER_ZIP" ]; then cp "$BROWSER_ZIP" "$B/browser/chrome-linux64.zip"; else curl --proto '=https' --tlsv1.2 -fsSL "https://storage.googleapis.com/chrome-for-testing-public/$CFT_VERSION/linux64/chrome-linux64.zip" -o "$B/browser/chrome-linux64.zip"; fi
    [ "$(sha256sum "$B/browser/chrome-linux64.zip" | cut -d' ' -f1)" = "$CFT_SHA256" ] || die "chrome-linux64.zip does not match the pinned sha256 $CFT_SHA256"
    echo "$CFT_VERSION" > "$B/browser/VERSION"
fi
echo "$ARCH" > "$B/ARCH"
( cd "$B" && find . -path ./release -prune -o -type f ! -name 'BUNDLE.sha256*' -print | sed 's|^\./||' | sort | xargs sha256sum > BUNDLE.sha256 )
if [ -n "$KEY" ]; then "$ROOT/packaging/release/sign.sh" "$B/BUNDLE.sha256" "$KEY" "$B/BUNDLE.sha256.sig" >/dev/null; fi
find "$STAGE" -type d -exec chmod 0755 {} +
OUT_ABS=$(cd -- "$(dirname -- "$OUT")" && pwd)/$(basename -- "$OUT")
( cd "$STAGE" && tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner --format=gnu -cf - ark-offline | gzip -n -9 > "$OUT_ABS" )
echo "$OUT_ABS"
