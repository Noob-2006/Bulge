#!/usr/bin/env bash
# Render the AUR PKGBUILD (+ .SRCINFO) for a release.
#
#   mkpkgbuild.sh --version V --sums SHA256SUMS [--base URL] [--out DIR]
#
# --sums is the release's SHA256SUMS (it lists the musl tarballs). --base defaults to the GitHub
# release download URL of that version. Without makepkg, .SRCINFO is written by this script.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VERSION="" SUMS="" BASE="" OUT=$PWD/aur
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION=${2:?}; shift ;;
        --sums) SUMS=${2:?}; shift ;;
        --base) BASE=${2:?}; shift ;;
        --out) OUT=${2:?}; shift ;;
        -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
    shift
done
[ -n "$VERSION" ] && [ -f "$SUMS" ] || { echo "need --version and --sums" >&2; exit 2; }
BASE=${BASE:-https://github.com/${SEAGENT_REPO:-Noob-2006/System-Engineering-Agent}/releases/download/v$VERSION}
sum() { awk -v f="$1" '$2 == f || $2 == "*"f { print $1 }' "$SUMS"; }
X86=$(sum seagent-x86_64-unknown-linux-musl.tar.gz) ARM=$(sum seagent-aarch64-unknown-linux-musl.tar.gz)
[ -n "$X86" ] && [ -n "$ARM" ] || { echo "SHA256SUMS lacks the musl tarballs" >&2; exit 1; }
mkdir -p "$OUT"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@BASE@|$BASE|g" -e "s|@SHA_X86_64@|$X86|g" -e "s|@SHA_AARCH64@|$ARM|g" "$HERE/PKGBUILD.in" > "$OUT/PKGBUILD"
cp "$HERE/seagent.install" "$OUT/"
if command -v makepkg >/dev/null 2>&1; then
    (cd "$OUT" && makepkg --printsrcinfo > .SRCINFO)
else
    cat > "$OUT/.SRCINFO" <<SRC
pkgbase = seagent-bin
	pkgdesc = SE Agent (System Engineering Agent): self-hosted, Linux-first AI agent runtime
	pkgver = $VERSION
	pkgrel = 1
	url = https://github.com/Noob-2006/System-Engineering-Agent
	install = seagent.install
	arch = x86_64
	arch = aarch64
	license = Apache-2.0
	optdepends = git: version control tools
	optdepends = qemu-system-x86: desktop and tool-isolation VMs
	optdepends = chromium: browser tools
	optdepends = libsecret: keyring-backed secret store
	provides = seagent
	conflicts = seagent
	conflicts = ark-agent
	replaces = ark-agent
	source_x86_64 = $BASE/seagent-x86_64-unknown-linux-musl.tar.gz
	sha256sums_x86_64 = $X86
	source_aarch64 = $BASE/seagent-aarch64-unknown-linux-musl.tar.gz
	sha256sums_aarch64 = $ARM

pkgname = seagent-bin
SRC
fi
echo "wrote $OUT/PKGBUILD, $OUT/seagent.install, $OUT/.SRCINFO"
