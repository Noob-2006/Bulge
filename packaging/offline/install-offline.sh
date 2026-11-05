#!/usr/bin/env bash
# Install seagent from an air-gapped bundle. No network is used, none is needed. The only commands
# it runs are tar/install/sha256sum/openssl, and (with --package) your package manager.
#
#   ./install-offline.sh [--prefix DIR] [--package] [--key release-key.pub.pem] [--vm-image-dir DIR] [--no-verify]
#
# Order matters (same as verify-release.sh): the signature comes first, then hashes, then install.
#   --key       public key obtained OUT OF BAND (the copy inside the bundle only detects corruption)
#   --prefix    default /usr/local when root, ~/.local otherwise
#   --package   install the matching .deb/.rpm with dpkg/rpm instead of unpacking the tarball
set -euo pipefail
export LC_ALL=C
PROG=$(basename "$0")
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
PREFIX="" PKG=0 KEY="" VMDIR="" VERIFY=1
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=${2:?}; shift ;;
        --package) PKG=1 ;;
        --key) KEY=${2:?}; shift ;;
        --vm-image-dir) VMDIR=${2:?}; shift ;;
        --no-verify) VERIFY=0 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
    shift
done
ARCH=$(cat "$HERE/ARCH")
[ "$(uname -m)" = "$ARCH" ] || die "this bundle is for $ARCH, this machine is $(uname -m)"
if [ -z "$PREFIX" ]; then if [ "$(id -u)" = 0 ]; then PREFIX=/usr/local; else PREFIX=$HOME/.local; fi; fi

if [ "$VERIFY" = 1 ]; then
    command -v openssl >/dev/null || die "openssl is needed to verify the signature (or pass --no-verify and accept the risk)"
    command -v python3 >/dev/null || die "python3 is needed to check the SBOM (or pass --no-verify)"
    if [ -f "$HERE/BUNDLE.sha256.sig" ] && [ -n "$KEY" ]; then
        say "[1/4] bundle signature"
        # BUNDLE.sha256.sig is the same base64 Ed25519 format sign.sh writes
        sig=$(mktemp); base64 -d "$HERE/BUNDLE.sha256.sig" > "$sig" 2>/dev/null || die "bad BUNDLE.sha256.sig"
        openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin -in "$HERE/BUNDLE.sha256" -sigfile "$sig" >/dev/null || die "BUNDLE.sha256 signature is invalid"
        rm -f "$sig"
    else
        say "[1/4] bundle signature: skipped (no BUNDLE.sha256.sig or no --key)"
    fi
    say "[2/4] bundle file hashes"
    ( cd "$HERE" && sha256sum -c --quiet BUNDLE.sha256 ) || die "a file in the bundle does not match BUNDLE.sha256"
    say "[3/4] release signature, hashes and SBOM"
    "$HERE/tools/verify-release.sh" "$HERE/release" --key "${KEY:-$HERE/release/release-key.pub.pem}" || die "release/ does not verify"
else
    say "WARNING: --no-verify: nothing was checked"
fi

say "[4/4] install"
if [ "$PKG" = 1 ]; then
    if command -v rpm >/dev/null 2>&1 && ls "$HERE"/release/seagent-*."$ARCH".rpm >/dev/null 2>&1; then
        rpm -Uvh "$HERE"/release/seagent-*."$ARCH".rpm
    elif command -v dpkg >/dev/null 2>&1 && ls "$HERE"/release/seagent_*.deb >/dev/null 2>&1; then
        case "$ARCH" in x86_64) da=amd64 ;; aarch64) da=arm64 ;; esac
        dpkg -i "$HERE"/release/seagent_*_"$da".deb
    else
        die "--package: no matching package manager/package in the bundle (use the tarball install)"
    fi
    P=/usr
else
    t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
    tar -xzf "$HERE/release/seagent-$ARCH-unknown-linux-musl.tar.gz" -C "$t"
    install -d "$PREFIX/bin" "$PREFIX/share"
    install -m 0755 "$t/bin/seagent" "$PREFIX/bin/seagent.new" && mv -f "$PREFIX/bin/seagent.new" "$PREFIX/bin/seagent"
    rm -rf "$PREFIX/share/seagent.new" && cp -R "$t/share/seagent" "$PREFIX/share/seagent.new" && rm -rf "$PREFIX/share/seagent" && mv "$PREFIX/share/seagent.new" "$PREFIX/share/seagent"
    P=$PREFIX
fi
if [ -d "$HERE/vm-image" ]; then
    dest=${VMDIR:-$P/share/seagent/vm-image}
    mkdir -p "$dest/image" && cp -R "$HERE/vm-image/." "$dest/image/"
    say "microVM guest image copied to $dest/image; point seagent at it:  seagent config set exec.vm.image_dir=$dest"
fi
if [ -f "$HERE/browser/chrome-linux64.zip" ]; then
    # Hash already checked against BUNDLE.sha256 above; unpack the pinned Chrome for Testing
    # where seagent's browser discovery looks (<share>/browsers/chrome-linux64/chrome).
    mkdir -p "$P/share/seagent/browsers" && rm -rf "$P/share/seagent/browsers/chrome-linux64"
    if command -v unzip >/dev/null 2>&1; then unzip -q -o "$HERE/browser/chrome-linux64.zip" -d "$P/share/seagent/browsers"; else python3 -I -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$HERE/browser/chrome-linux64.zip" "$P/share/seagent/browsers"; fi
    chmod 0755 "$P/share/seagent/browsers/chrome-linux64/chrome" "$P/share/seagent/browsers/chrome-linux64/chrome_crashpad_handler" 2>/dev/null || true
    cp "$HERE/browser/VERSION" "$P/share/seagent/browsers/chrome-linux64/.seagent-version" 2>/dev/null || true
    say "bundled Chrome for Testing → $P/share/seagent/browsers/chrome-linux64 (prefer it: seagent config set browser.prefer_bundled=true)"
fi
"$P/bin/seagent" --version
say "installed. Next: seagent doctor"
