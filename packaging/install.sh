#!/bin/sh
# ark installer.  curl --proto '=https' --tlsv1.2 -fsSL <url>/install.sh | sh
# Options: --from-source  --service  --version vX.Y.Z   Env: ARK_INSTALL_DIR, ARK_REPO
# Never uses sudo; installs to ~/.local/bin by default; verifies SHA256SUMS
# (and the GitHub build attestation when `gh` is available).
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
        need cargo
        say "building from source (cargo install)…"
        cargo install --locked --git "https://github.com/$repo" --bin ark --root "$dir/.." ark
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
        if [ "$version" = latest ]; then base="https://github.com/$repo/releases/latest/download"; else base="https://github.com/$repo/releases/download/$version"; fi
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        fetch "$base/ark-$target.tar.gz" "$tmp/ark-$target.tar.gz"
        fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
        (cd "$tmp" && verify_sum "ark-$target.tar.gz")
        if command -v gh >/dev/null 2>&1; then
            gh attestation verify "$tmp/ark-$target.tar.gz" -R "$repo" >/dev/null 2>&1 && say "build provenance verified" || say "warning: could not verify the build attestation (gh not logged in?)"
        fi
        tar -xzf "$tmp/ark-$target.tar.gz" -C "$tmp"
        install -m 0755 "$tmp/ark" "$dir/ark.new"
        mv -f "$dir/ark.new" "$dir/ark"
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

say() { printf '%s\n' "ark-install: $*"; }
err() { say "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "needs $1"; }

fetch() {
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
