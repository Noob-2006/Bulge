#!/bin/sh
# seagent one-command installer: installs, starts the service and the web console, and prints a
# one-time link to the browser setup wizard.
#
#   curl --proto '=https' --tlsv1.2 -fsSL <url>/install.sh | sh                 # user install, no sudo
#   curl ... | sudo sh -s -- --system                                          # system service (FHS)
#
# Options:
#   --user | --system      install for this user (default; XDG dirs, systemd user unit) or as a
#                          system service (root; account `seagent`, /etc/seagent, /var/lib/seagent, ...)
#   --port N               web console port on 127.0.0.1 (default 8640, or the configured one)
#   --version vX.Y.Z       release to install (default: latest)
#   --local-binary PATH    install this seagent binary instead of downloading (share data from
#                          SEAGENT_SHARE_SRC, an unpacked tarball, or the checkout next to the binary)
#   --package FILE         system install from a .deb/.rpm instead of the tarball
#   --from-source          build with cargo
#   --no-start             install only; do not configure or start anything
#   --no-systemd           do not use systemd; run `seagent daemon` in the background
#   --no-browser           do not open a browser
#   --with-browser         also install the pinned Chrome for Testing build (sha256-verified) into
#                          <share>/browsers/chrome-linux64; seagent finds it (browser.prefer_bundled = true
#                          makes it win over host browsers). From an offline bundle: browser/*.zip
#   --uninstall [--purge]  remove seagent (keeps config and data unless --purge)
#   -y, --yes              no questions (take the defaults)
# Env: SEAGENT_RELEASE_BASE (mirror dir or file:// URL), SEAGENT_RELEASE_PUBKEY (release-key.pub.pem to
#      verify SHA256SUMS.sig), SEAGENT_INSTALL_DIR (user mode binary dir), SEAGENT_REPO, NO_COLOR.
# Re-running upgrades in place. POSIX sh; works on Alpine/busybox and from an offline bundle
# (run it from the unpacked bundle: release/ is used and nothing is downloaded).
set -eu
(set -o pipefail) 2>/dev/null && set -o pipefail

# Distros with user private groups default to umask 002; an installed runtime that is
# group-writable fails its own ownership checks. Remove group/world write while keeping
# a stricter caller mask (umask 077 stays 077).
umask go-w

STEPS=7
step=0
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then B=$(printf '\033[1m'); D=$(printf '\033[2m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m'); R=$(printf '\033[31m'); C=$(printf '\033[36m'); N=$(printf '\033[0m'); else B= D= G= Y= R= C= N=; fi
say() { printf '%s\n' "seagent-install: $*"; }
next() { step=$((step + 1)); printf '%s[%d/%d]%s %s\n' "$B$C" "$step" "$STEPS" "$N" "$*"; }
ok() { printf '      %s✓%s %s\n' "$G" "$N" "$*"; }
note() { printf '      %s%s%s\n' "$D" "$*" "$N"; }
warn() { printf '      %s!%s %s\n' "$Y" "$N" "$*" >&2; }
err() { printf '%sseagent-install: error:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "needs $1"; }

main() {
    repo="${SEAGENT_REPO:-Noob-2006/System-Engineering-Agent}"
    version=latest mode="" port="" local_bin="" package="" from_source=0 start=1 use_systemd=auto browser=1 uninstall=0 purge=0 assume_yes=0 with_browser=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --user) mode=user ;;
            --system) mode=system ;;
            --port) shift; port="${1:-}" ;;
            --version) shift; version="${1:-}" ;;
            --local-binary) shift; local_bin="${1:-}" ;;
            --package) shift; package="${1:-}" ;;
            --from-source) from_source=1 ;;
            --service) ;; # old flag: the service is always installed now
            --no-start) start=0 ;;
            --no-systemd) use_systemd=no ;;
            --no-browser) browser=0 ;;
            --with-browser) with_browser=1 ;;
            --uninstall) uninstall=1 ;;
            --purge) purge=1 ;;
            -y|--yes) assume_yes=1 ;;
            -h|--help) sed -n '2,30p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; return 0 ;;
            *) err "unknown option $1 (see --help)" ;;
        esac
        shift
    done
    case "$port" in ''|*[!0-9]*) [ -z "$port" ] || err "--port wants a number" ;; esac

    choose_mode
    if [ "$mode" = system ]; then
        [ "$(id -u)" = 0 ] || err "a system install needs root: re-run with sudo (or use --user)"
        bin_dir=/usr/local/bin share_dir=/usr/local/share/seagent
    else
        [ "$(id -u)" = 0 ] && [ -z "${SEAGENT_INSTALL_DIR:-}" ] && warn "running as root: this is a user install for root (use --system for a service)"
        bin_dir="${SEAGENT_INSTALL_DIR:-$HOME/.local/bin}"
        # Not ../share/seagent: with ~/.local/bin that is seagent's own data dir.
        share_dir="$(dirname "$bin_dir")/lib/seagent/share"
    fi
    if [ "$use_systemd" = auto ]; then
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            if [ "$mode" = system ] || systemctl --user show-environment >/dev/null 2>&1; then use_systemd=yes; else use_systemd=no; fi
        else
            use_systemd=no
        fi
    fi
    [ "$uninstall" = 1 ] && { do_uninstall; return 0; }
    [ "$start" = 1 ] || STEPS=3

    next "platform"
    detect_platform
    ok "$distro $(uname -m), $mode install${D} (bin $bin_dir)${N}"

    next "fetch and verify"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM
    obtain

    next "install"
    install_files
    [ "$with_browser" = 1 ] && install_browser
    case ":$PATH:" in *":$bin_dir:"*) ;; *) [ "$mode" = user ] && warn "add $bin_dir to PATH: echo 'export PATH=\"$bin_dir:\$PATH\"' >> ~/.profile" ;; esac
    if [ "$start" = 0 ]; then
        note "not started (--no-start). Later: seagent setup bootstrap && seagent daemon start && seagent setup link"
        return 0
    fi

    next "configure"
    configure

    next "service"
    start_service

    next "health"
    wait_health

    next "setup link"
    finish
}

# ───────────── mode, platform ─────────────

choose_mode() {
    [ -n "$mode" ] && return 0
    mode=user
    if [ "$assume_yes" = 0 ] && [ -t 0 ] && [ -r /dev/tty ]; then
        printf '%sInstall seagent for%s  [1] this user (no sudo, default)   [2] the whole machine as a system service: ' "$B" "$N"
        read -r a </dev/tty || a=
        case "$a" in 2|s|system) mode=system ;; esac
    fi
}

detect_platform() {
    distro=linux
    if [ -r /etc/os-release ]; then distro=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${ID:-linux}}"); fi
    [ "$(uname -s)" = Linux ] || [ -n "$local_bin" ] || [ "$from_source" = 1 ] || err "prebuilt binaries are Linux-only; use --from-source"
    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) [ -n "$local_bin" ] || [ "$from_source" = 1 ] || err "unsupported CPU $(uname -m); use --from-source" ; arch=$(uname -m) ;;
    esac
    # The musl build is static: no glibc version to match.
    target="$arch-unknown-linux-musl"
}

# ───────────── fetch ─────────────

obtain() {
    src_bin="" src_share=""
    if [ -n "$package" ]; then
        [ "$mode" = system ] || err "--package is for --system installs"
        [ -f "$package" ] || err "--package: no such file $package"
        ok "package $(basename "$package")"
        return 0
    fi
    if [ -n "$local_bin" ]; then
        [ -x "$local_bin" ] || err "--local-binary: $local_bin is not an executable"
        src_bin="$local_bin"
        here=$(cd "$(dirname "$local_bin")" && pwd)
        for s in "${SEAGENT_SHARE_SRC:-}" "$here/../share/seagent" "$here/../lib/seagent/share"; do
            [ -n "$s" ] && [ -d "$s/skills" ] && { src_share="$s"; break; }
        done
        if [ -z "$src_share" ]; then
            # a cargo target dir inside a checkout, or this script's own checkout
            script_root=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || echo /nonexistent)
            d="$here"
            while [ "$d" != / ]; do
                if [ -d "$d/share/skills" ] && [ -f "$d/Cargo.toml" ]; then stage_checkout_share "$d"; break; fi
                d=$(dirname "$d")
            done
            if [ -z "$src_share" ] && [ -d "$script_root/share/skills" ] && [ -f "$script_root/Cargo.toml" ]; then stage_checkout_share "$script_root"; fi
        fi
        ok "local binary $local_bin ($("$local_bin" --version 2>/dev/null || echo '?'))"
        [ -n "$src_share" ] || warn "no share data found next to the binary (skills, roles); set SEAGENT_SHARE_SRC"
        return 0
    fi
    if [ "$from_source" = 1 ]; then
        need cargo; need git
        note "building from source (cargo install)…"
        if [ "$version" = latest ]; then git clone -q --depth 1 "https://github.com/$repo" "$tmp/src"; else git clone -q --depth 1 --branch "$version" "https://github.com/$repo" "$tmp/src"; fi
        cargo install -q --locked --path "$tmp/src/crates/seagent" --root "$tmp/root" --bin seagent
        src_bin="$tmp/root/bin/seagent"
        stage_checkout_share "$tmp/src"
        ok "built $("$src_bin" --version 2>/dev/null)"
        return 0
    fi
    need tar
    here=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)
    if [ -n "${SEAGENT_RELEASE_BASE:-}" ]; then base="${SEAGENT_RELEASE_BASE%/}"
    elif [ -f "$here/release/seagent-$target.tar.gz" ]; then base="file://$here/release"; note "offline bundle: $here/release"
    elif [ "$version" = latest ]; then base="https://github.com/$repo/releases/latest/download"
    else base="https://github.com/$repo/releases/download/$version"; fi
    fetch "$base/seagent-$target.tar.gz" "$tmp/seagent-$target.tar.gz"
    fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
    (cd "$tmp" && verify_sum "seagent-$target.tar.gz")
    verify_signature "$base" "$tmp"
    if [ -z "${SEAGENT_RELEASE_BASE:-}" ] && case "$base" in file://*) false ;; *) true ;; esac && command -v gh >/dev/null 2>&1; then
        if gh attestation verify "$tmp/seagent-$target.tar.gz" -R "$repo" >/dev/null 2>&1; then ok "build provenance verified"; else warn "could not verify the build attestation (gh not logged in?)"; fi
    fi
    mkdir -p "$tmp/x"
    tar -xzf "$tmp/seagent-$target.tar.gz" -C "$tmp/x"
    [ -f "$tmp/x/bin/seagent" ] || err "the archive has no bin/seagent"
    src_bin="$tmp/x/bin/seagent"
    [ -d "$tmp/x/share/seagent" ] && src_share="$tmp/x/share/seagent"
}

# A checkout's share/ plus the vm builder and sandbox-browser sources (the tarball layout).
stage_checkout_share() {
    mkdir -p "$tmp/share/vm" "$tmp/share/sandbox-browser"
    cp -R "$1/share/." "$tmp/share/"
    [ -f "$1/packaging/vm/build-image.sh" ] && cp -R "$1/packaging/vm/." "$tmp/share/vm/" 2>/dev/null || true
    [ -d "$1/packaging/sandbox-browser" ] && cp -R "$1/packaging/sandbox-browser/." "$tmp/share/sandbox-browser/"
    src_share="$tmp/share"
}

fetch() {
    case "$1" in
        file://*) cp "${1#file://}" "$2" 2>/dev/null || err "cannot read $1"; return 0 ;;
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
        printf '%s\n' "$line" | sha256sum -c - >/dev/null 2>&1 || err "checksum mismatch for $1"
    else
        want="${line%% *}"
        got="$(shasum -a 256 "$1" | cut -d' ' -f1)"
        [ "$want" = "$got" ] || err "checksum mismatch for $1"
    fi
    ok "checksum ok"
}

# Ed25519 signature over SHA256SUMS (packaging/release/sign.sh). Only when the caller supplies
# the public key they trust (SEAGENT_RELEASE_PUBKEY); then a missing or bad signature is fatal.
verify_signature() {
    [ -n "${SEAGENT_RELEASE_PUBKEY:-}" ] || return 0
    need openssl
    [ -f "$SEAGENT_RELEASE_PUBKEY" ] || err "SEAGENT_RELEASE_PUBKEY=$SEAGENT_RELEASE_PUBKEY is not a file"
    fetch "$1/SHA256SUMS.sig" "$2/SHA256SUMS.sig"
    openssl base64 -d -A -in "$2/SHA256SUMS.sig" -out "$2/SHA256SUMS.sig.bin" 2>/dev/null || err "SHA256SUMS.sig is not base64"
    openssl pkeyutl -verify -pubin -inkey "$SEAGENT_RELEASE_PUBKEY" -rawin -in "$2/SHA256SUMS" -sigfile "$2/SHA256SUMS.sig.bin" >/dev/null 2>&1 || err "signature of SHA256SUMS does not verify against $SEAGENT_RELEASE_PUBKEY"
    ok "release signature verified"
}

# Pinned Chrome for Testing (same values as seagent_browser::launch::PINNED_CFT_*).
CFT_VERSION=157.0.8103.38
CFT_SHA256=8cdeb344e9b2cefe59f4aea8d1d93d5d93054c03cde217665c16fc1f62e72a66
CFT_URL="https://storage.googleapis.com/chrome-for-testing-public/$CFT_VERSION/linux64/chrome-linux64.zip"

# --with-browser: the pinned build into <share>/browsers/chrome-linux64 (after install_files,
# which replaces <share>). An offline bundle's browser/chrome-linux64.zip is used when present.
install_browser() {
    [ "$(uname -m)" = x86_64 ] || { warn "--with-browser: Chrome for Testing has no linux $(uname -m) build; skipped"; return 0; }
    zip="$tmp/chrome-linux64.zip"
    here=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)
    if [ -f "$here/browser/chrome-linux64.zip" ]; then
        cp "$here/browser/chrome-linux64.zip" "$zip"
        note "browser from the offline bundle"
    else
        fetch "${SEAGENT_BROWSER_URL:-$CFT_URL}" "$zip"
    fi
    if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$zip" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$zip" | cut -d' ' -f1)"; fi
    [ "$got" = "$CFT_SHA256" ] || err "Chrome for Testing archive sha256 $got does not match the pinned $CFT_SHA256"
    mkdir -p "$share_dir/browsers"
    rm -rf "$share_dir/browsers/chrome-linux64"
    if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$zip" -d "$share_dir/browsers" || err "unzip failed"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$zip" "$share_dir/browsers" || err "unpacking failed"
    else
        err "--with-browser needs unzip or python3"
    fi
    chmod 0755 "$share_dir/browsers/chrome-linux64/chrome" "$share_dir/browsers/chrome-linux64/chrome_crashpad_handler" 2>/dev/null || true
    printf '%s\n' "$CFT_VERSION" > "$share_dir/browsers/chrome-linux64/.seagent-version"
    rm -f "$zip"
    ok "Chrome for Testing $CFT_VERSION (sha256 ok) → $share_dir/browsers/chrome-linux64"
    note "prefer it over host browsers: seagent config set browser.prefer_bundled=true"
}

# ───────────── install ─────────────

install_files() {
    if [ -n "$package" ]; then
        case "$package" in
            *.deb) need dpkg; dpkg -i "$package" >"$tmp/pkg.log" 2>&1 || { cat "$tmp/pkg.log" >&2; err "dpkg -i failed"; } ;;
            *.rpm) need rpm; rpm -Uvh --replacepkgs "$package" >"$tmp/pkg.log" 2>&1 || { cat "$tmp/pkg.log" >&2; err "rpm -U failed"; } ;;
            *) err "--package wants a .deb or .rpm" ;;
        esac
        bin_dir=/usr/bin share_dir=/usr/share/seagent
        ok "installed $(basename "$package") (/usr/bin/seagent, /usr/share/seagent)"
        seagent="$bin_dir/seagent"
        [ "$mode" = system ] && system_account
        return 0
    fi
    mkdir -p "$bin_dir"
    install -m 0755 "$src_bin" "$bin_dir/seagent.new"
    mv -f "$bin_dir/seagent.new" "$bin_dir/seagent"
    seagent="$bin_dir/seagent"
    mkdir -p "$(dirname "$share_dir")"
    rm -rf "$share_dir.new" "$share_dir.old"
    if [ -n "$src_share" ]; then cp -R "$src_share" "$share_dir.new"; else mkdir -p "$share_dir.new"; fi
    # the installer itself, so uninstall (and a re-run without the network) work later
    [ -f "$0" ] && cp "$0" "$share_dir.new/install.sh" 2>/dev/null || true
    [ -d "$share_dir" ] && mv "$share_dir" "$share_dir.old"
    mv "$share_dir.new" "$share_dir"
    rm -rf "$share_dir.old"
    ok "$("$seagent" --version 2>/dev/null || echo seagent) → $seagent"
    [ -n "$src_share" ] && note "bundled skills and catalogs → $share_dir"
    [ "$mode" = system ] && system_account
    return 0
}

# The dedicated account and the FHS directories (what the deb/rpm scriptlets do).
system_account() {
    if ! id seagent >/dev/null 2>&1; then
        if command -v useradd >/dev/null 2>&1; then
            getent group seagent >/dev/null 2>&1 || groupadd -r seagent
            useradd -r -g seagent -d /var/lib/seagent -s /usr/sbin/nologin -c "seagent agent" seagent 2>/dev/null || useradd -r -g seagent -d /var/lib/seagent -s /sbin/nologin -c "seagent agent" seagent
        elif command -v adduser >/dev/null 2>&1; then
            addgroup -S seagent 2>/dev/null || true
            adduser -S -D -H -h /var/lib/seagent -s /sbin/nologin -G seagent seagent
        else
            err "cannot create the seagent account (no useradd/adduser)"
        fi
        ok "created system account seagent"
    fi
    for d in /var/lib/seagent /var/lib/seagent/workspace /var/cache/seagent /var/log/seagent /run/seagent; do
        install -d -o seagent -g seagent -m 0750 "$d"
    done
    install -d -o root -g seagent -m 1770 /etc/seagent
    [ -d /etc/seagent/managed.d ] || install -d -o root -g root -m 0755 /etc/seagent/managed.d
}

# Run seagent as the account that owns the installation.
as_owner() {
    if [ "$mode" = system ]; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u seagent -- env -u SEAGENT_HOME HOME=/var/lib/seagent SEAGENT_MODE=system "$seagent" "$@"
        elif command -v setpriv >/dev/null 2>&1; then
            setpriv --reuid=seagent --regid=seagent --clear-groups env -u SEAGENT_HOME HOME=/var/lib/seagent SEAGENT_MODE=system "$seagent" "$@"
        elif command -v su >/dev/null 2>&1; then
            cmd="SEAGENT_MODE=system HOME=/var/lib/seagent '$seagent'"
            for a in "$@"; do cmd="$cmd '$a'"; done
            su -s /bin/sh seagent -c "$cmd"
        else
            # minimal images without util-linux: coreutils' chroot can drop to the account too
            chroot --userspec=seagent:seagent --groups=seagent / env -u SEAGENT_HOME HOME=/var/lib/seagent SEAGENT_MODE=system "$seagent" "$@"
        fi
    else
        "$seagent" "$@"
    fi
}

# ───────────── configure, service, health ─────────────

configure() {
    if [ -n "$port" ]; then out=$(as_owner setup bootstrap --listen "127.0.0.1:$port" 2>&1) || { printf '%s\n' "$out" >&2; err "seagent setup bootstrap failed"; }
    else out=$(as_owner setup bootstrap 2>&1) || { printf '%s\n' "$out" >&2; err "seagent setup bootstrap failed"; }; fi
    console=$(printf '%s\n' "$out" | sed -n 's/.*console: \(http[^ ]*\).*/\1/p' | tail -n 1)
    [ -n "$console" ] || console="http://127.0.0.1:${port:-8640}"
    ws=$(path_json workspace)
    [ -n "$ws" ] || ws=$(pwd)
    [ "$mode" = system ] || mkdir -p "$ws"
    ok "web console enabled on ${console#http://}"
    note "layout: $(as_owner config path 2>/dev/null | sed -n 's/^mode *//p')"
}

# One field of `seagent config path --json` (the layout seagent itself resolved).
path_json() {
    as_owner config path --json 2>/dev/null | sed -n "s/^ *\"$1\": \"\(.*\)\",\{0,1\}\$/\1/p"
}

start_service() {
    if [ "$mode" = system ]; then
        if [ "$use_systemd" = yes ]; then
            if [ -z "$package" ]; then
                env -u SEAGENT_HOME -u SEAGENT_PROFILE -u SEAGENT_MODE "$seagent" service print --system > /etc/systemd/system/seagentd.service.new
                mv -f /etc/systemd/system/seagentd.service.new /etc/systemd/system/seagentd.service
            fi
            systemctl daemon-reload
            systemctl enable seagentd.service >/dev/null 2>&1 || warn "systemctl enable seagentd failed"
            systemctl restart seagentd.service || err "systemctl restart seagentd failed (journalctl -u seagentd)"
            ok "seagentd.service enabled and (re)started"
        else
            as_owner daemon stop >/dev/null 2>&1 || true
            as_owner daemon start -w "$ws" >/dev/null || err "seagent daemon start failed (see /var/log/seagent/seagentd.log)"
            ok "seagentd running in the background (no systemd: it will not start at boot)"
        fi
    else
        if [ "$use_systemd" = yes ]; then
            if out=$("$seagent" service install -w "$ws" 2>&1); then
                systemctl --user restart "$(unit_name)" >/dev/null 2>&1 || true
                ok "$(unit_name) (systemd user unit) enabled and started"
            else
                printf '%s\n' "$out" >&2
                warn "systemd user unit failed; falling back to a background daemon"
                use_systemd=no
            fi
        fi
        if [ "$use_systemd" = no ]; then
            "$seagent" daemon stop >/dev/null 2>&1 || true
            "$seagent" daemon start -w "$ws" >/dev/null || err "seagent daemon start failed (seagent logs)"
            ok "seagentd running in the background (no systemd user session: start it after a reboot with: seagent daemon start)"
        fi
    fi
}

unit_name() { echo seagentd.service; }

http_ok() {
    if command -v curl >/dev/null 2>&1; then curl -fsS -m 2 "$1" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then wget -q -T 2 -O /dev/null "$1" 2>/dev/null
    else "$seagent" health >/dev/null 2>&1; fi
}

wait_health() {
    i=0
    while [ $i -lt 60 ]; do
        if http_ok "$console/health"; then ok "daemon and web console answer on $console"; return 0; fi
        i=$((i + 1)); sleep 0.5
    done
    if [ "$mode" = system ] && [ "$use_systemd" = yes ]; then err "the console did not come up in 30s (journalctl -u seagentd -n 50)"; fi
    err "the console did not come up in 30s (seagent logs; seagent doctor)"
}

finish() {
    if link=$(as_owner setup link 2>/dev/null); then
        ok "one-time setup link (30 minutes, single use):"
        printf '\n      %s%s%s\n\n' "$B" "$link" "$N"
        if [ "$browser" = 1 ] && [ "$mode" = user ] && { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; } && command -v xdg-open >/dev/null 2>&1; then
            xdg-open "$link" >/dev/null 2>&1 &
            note "opened in your browser"
        elif [ "$mode" = system ]; then
            note "on another machine: ssh -L ${console##*:}:127.0.0.1:${console##*:} <this host>, then open the link"
        fi
    else
        ok "already set up: open the console with  seagent app open   (${console})"
        note "re-run the wizard: seagent setup link --reopen"
    fi
    if [ "$mode" = system ]; then
        note "config /etc/seagent · data /var/lib/seagent · logs /var/log/seagent · seagent config path"
    else
        note "terminal setup instead: seagent setup · status: seagent doctor · remove: sh $share_dir/install.sh --uninstall"
    fi
}

# ───────────── uninstall ─────────────

do_uninstall() {
    STEPS=3
    if [ "$mode" = system ]; then
        [ -x /usr/bin/seagent ] && command -v dpkg >/dev/null 2>&1 && dpkg -S /usr/bin/seagent >/dev/null 2>&1 && pkg=deb
        [ -x /usr/bin/seagent ] && command -v rpm >/dev/null 2>&1 && rpm -qf /usr/bin/seagent >/dev/null 2>&1 && pkg=rpm
        seagent=$(command -v seagent || echo /usr/local/bin/seagent)
    else
        seagent="$bin_dir/seagent"
    fi
    next "stop the service"
    if [ "$mode" = system ]; then
        if command -v systemctl >/dev/null 2>&1; then systemctl disable --now seagentd.service >/dev/null 2>&1 || true; fi
        [ -x "$seagent" ] && as_owner daemon stop >/dev/null 2>&1 || true
        [ "${pkg:-}" ] || rm -f /etc/systemd/system/seagentd.service
    else
        if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then systemctl --user disable --now seagentd.service >/dev/null 2>&1 || true; fi
        [ -x "$seagent" ] && "$seagent" daemon stop >/dev/null 2>&1 || true
        rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/seagentd.service"
        command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload >/dev/null 2>&1 || true
    fi
    ok "stopped"
    dirs=""
    if [ "$purge" = 1 ] && [ -x "$seagent" ]; then
        dirs="$(path_json data) $(path_json cache) $(path_json logs) $(path_json runtime)"
        cfg=$(path_json config)
    fi
    next "remove the program"
    if [ "${pkg:-}" = deb ]; then apt-get remove -y seagent >/dev/null 2>&1 || dpkg -r seagent >/dev/null
    elif [ "${pkg:-}" = rpm ]; then (command -v dnf >/dev/null 2>&1 && dnf remove -y seagent >/dev/null) || rpm -e seagent
    else
        rm -f "$seagent"
        rm -rf "$share_dir"
        [ "$mode" = user ] && rmdir "$(dirname "$share_dir")" 2>/dev/null || true
    fi
    ok "removed"
    next "data"
    if [ "$purge" = 1 ]; then
        for d in $dirs; do
            case "$d" in */seagent|*/seagent/*|*/seagent/data|*/seagent/run|*/seagent/logs) rm -rf "$d" ;; esac
        done
        if [ -n "${cfg:-}" ]; then
            cdir=$(dirname "$cfg")
            if [ "$mode" = system ]; then
                rm -f "$cdir/config.toml" "$cdir"/config.toml.bak.* "$cdir"/secrets.* "$cdir/.env"
                rm -rf /var/lib/seagent /var/cache/seagent /var/log/seagent /run/seagent
                userdel seagent 2>/dev/null || deluser seagent 2>/dev/null || true
                note "organisation policy in /etc/seagent/managed* was kept"
            else
                case "$cdir" in */seagent) rm -rf "$cdir" ;; esac
            fi
        fi
        ok "config, data, cache and logs erased"
    else
        ok "config and data kept (erase them with --uninstall --purge)"
    fi
}

main "$@"
