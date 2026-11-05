#!/bin/sh
# ark installer.  curl --proto '=https' --tlsv1.2 -fsSL <url>/install.sh | sh
# Options: --from-source  --service  --version vX.Y.Z   Env: ARK_INSTALL_DIR, ARK_REPO, ARK_RELEASE_PUBKEY, ARK_RELEASE_BASE (mirror dir or file:// URL)
# Never uses sudo; installs to ~/.local/bin (+ ~/.local/lib/ark/share for the bundled skills, roles,
# catalogs) by default; verifies SHA256SUMS, the Ed25519 signature of SHA256SUMS when
# ARK_RELEASE_PUBKEY (path to release-key.pub.pem) is set, and the GitHub build attestation
# when `gh` is available. Works on Alpine/busybox (POSIX sh, wget or curl, musl static build).
set -eu
(set -o pipefail) 2>/dev/null && set -o pipefail

main() {
    repo="${ARK_REPO:-ark-agent/ark}"
    dir="${ARK_INSTALL_DIR:-$HOME/.local/bin}"
    version="latest"
    from_source=0
    service=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --from-source) from_source=1 ;;
            --service) service=1 ;;
            --version) shift; version="$1" ;;
            -h|--help) sed -n '2,5p' "$0" 2>/dev/null || true; return 0 ;;
            *) err "unknown option $1" ;;
        esac
        shift
    done
    [ "$(id -u)" = 0 ] && say "note: running as root; installing for root only."
    mkdir -p "$dir"

    if [ "$from_source" = 1 ]; then
        need cargo; need git
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        say "building from source (cargo install)…"
        if [ "$version" = latest ]; then git clone --depth 1 "https://github.com/$repo" "$tmp/src"; else git clone --depth 1 --branch "$version" "https://github.com/$repo" "$tmp/src"; fi
        cargo install --locked --path "$tmp/src/crates/ark" --root "$dir/.." --bin ark
        install_share "$tmp/src" "$dir/../lib/ark/share" source
    else
        need uname; need tar
        case "$(uname -m)" in
            x86_64|amd64) arch=x86_64 ;;
            aarch64|arm64) arch=aarch64 ;;
            *) err "unsupported CPU $(uname -m); use --from-source" ;;
        esac
        [ "$(uname -s)" = Linux ] || err "prebuilt binaries are Linux-only; use --from-source"
        # The musl build is static: no glibc version to match.
        target="$arch-unknown-linux-musl"
        if [ -n "${ARK_RELEASE_BASE:-}" ]; then base="${ARK_RELEASE_BASE%/}"
        elif [ "$version" = latest ]; then base="https://github.com/$repo/releases/latest/download"; else base="https://github.com/$repo/releases/download/$version"; fi
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        fetch "$base/ark-$target.tar.gz" "$tmp/ark-$target.tar.gz"
        fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
        (cd "$tmp" && verify_sum "ark-$target.tar.gz")
        verify_signature "$base" "$tmp"
        if [ -z "${ARK_RELEASE_BASE:-}" ] && command -v gh >/dev/null 2>&1; then
            if gh attestation verify "$tmp/ark-$target.tar.gz" -R "$repo" >/dev/null 2>&1; then say "build provenance verified"; else say "warning: could not verify the build attestation (gh not logged in?)"; fi
        fi
        mkdir -p "$tmp/x"
        tar -xzf "$tmp/ark-$target.tar.gz" -C "$tmp/x"
        [ -f "$tmp/x/bin/ark" ] || err "the archive has no bin/ark"
        install -m 0755 "$tmp/x/bin/ark" "$dir/ark.new"
        mv -f "$dir/ark.new" "$dir/ark"
        # Bundled data goes to <install dir>/../lib/ark/share, where `ark` looks for it. Not
        # ../share/ark: with the default ~/.local/bin that is ark's own data dir.
        install_share "$tmp/x" "$dir/../lib/ark/share" tarball
    fi
    say "installed $("$dir/ark" --version 2>/dev/null || echo ark) to $dir/ark"
    case ":$PATH:" in *":$dir:"*) ;; *) say "add $dir to your PATH, e.g. echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;; esac
    if [ "$service" = 1 ]; then
        "$dir/ark" service install
    else
        say "start the background service with: ark service install"
    fi
    say "your data (~/.local/share/ark) and config (~/.config/ark) were not touched."
}

# install_share <unpacked tarball | source checkout> <dest> <tarball|source>
install_share() {
    src="$1"; dest="$2"
    mkdir -p "$(dirname "$dest")"
    rm -rf "$dest.new" "$dest.old"
    if [ "$3" = tarball ]; then
        [ -d "$src/share/ark" ] || return 0
        cp -R "$src/share/ark" "$dest.new"
    else
        mkdir -p "$dest.new/vm" "$dest.new/sandbox-browser"
        cp -R "$src/share/." "$dest.new/"
        cp "$src/packaging/vm/build-image.sh" "$src/packaging/vm/README.md" "$dest.new/vm/"
        cp -R "$src/packaging/sandbox-browser/." "$dest.new/sandbox-browser/"
    fi
    [ -d "$dest" ] && mv "$dest" "$dest.old"
    mv "$dest.new" "$dest"
    rm -rf "$dest.old"
    say "installed bundled skills and catalogs to $dest"
}

# Ed25519 signature over SHA256SUMS (packaging/release/sign.sh). Only when the caller supplies
# the public key they trust (ARK_RELEASE_PUBKEY); then a missing or bad signature is fatal.
verify_signature() {
    [ -n "${ARK_RELEASE_PUBKEY:-}" ] || return 0
    need openssl
    [ -f "$ARK_RELEASE_PUBKEY" ] || err "ARK_RELEASE_PUBKEY=$ARK_RELEASE_PUBKEY is not a file"
    fetch "$1/SHA256SUMS.sig" "$2/SHA256SUMS.sig"
    openssl base64 -d -A -in "$2/SHA256SUMS.sig" -out "$2/SHA256SUMS.sig.bin" 2>/dev/null || err "SHA256SUMS.sig is not base64"
    openssl pkeyutl -verify -pubin -inkey "$ARK_RELEASE_PUBKEY" -rawin -in "$2/SHA256SUMS" -sigfile "$2/SHA256SUMS.sig.bin" >/dev/null 2>&1 || err "signature of SHA256SUMS does not verify against $ARK_RELEASE_PUBKEY"
    say "release signature verified"
}

say() { printf '%s\n' "ark-install: $*"; }
err() { say "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "needs $1"; }

fetch() {
    case "$1" in
        file://*) cp "${1#file://}" "$2" || err "cannot read $1"; return 0 ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2" || err "download failed: $1"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -q "$1" -O "$2" || err "download failed: $1"
    else
        err "needs curl or wget"
    fi
}

verify_sum() {
    line="$(grep " $1\$" SHA256SUMS || true)"
    [ -n "$line" ] || err "$1 is not listed in SHA256SUMS"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s\n' "$line" | sha256sum -c - >/dev/null || err "checksum mismatch for $1"
    else
        want="${line%% *}"
        got="$(shasum -a 256 "$1" | cut -d' ' -f1)"
        [ "$want" = "$got" ] || err "checksum mismatch for $1"
    fi
    say "checksum ok"
}

main "$@"
