#!/usr/bin/env bash
# Build seagent_<ver>-1_<arch>.deb, seagent-<ver>-1.<rpmarch>.rpm, seagent-<ver>-1-<arch>.pkg.tar.zst
# (pacman) and seagent_<ver>-r1_<arch>.apk (Alpine) from a prebuilt (static musl) binary.
#
#   build-packages.sh --bin PATH --arch amd64|arm64 [--version V] [--out DIR] [--nfpm CMD]
#
# nfpm comes from, in order: --nfpm CMD / $NFPM, an `nfpm` on PATH, the goreleaser/nfpm container
# (podman or docker; the container is named seagent-pkg-nfpm-* and removed afterwards).
# Layout: /usr/bin/seagent, /usr/share/seagent, /etc/seagent, /usr/lib/{systemd/system,sysusers.d,tmpfiles.d};
# /var/lib/seagent is created by systemd-tmpfiles (or postinstall.sh), never owned by the package.
set -euo pipefail
export LC_ALL=C
PROG=$(basename "$0")
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

BIN="" ARCH="" VERSION="" OUT="$PWD/dist" NFPM_CMD=${NFPM:-}
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=${2:?}; shift ;;
        --arch) ARCH=${2:?}; shift ;;
        --version) VERSION=${2:?}; shift ;;
        --out) OUT=${2:?}; shift ;;
        --nfpm) NFPM_CMD=${2:?}; shift ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
    shift
done
[ -f "$BIN" ] || die "--bin: no such file: $BIN"
case "$ARCH" in amd64|arm64) ;; *) die "--arch must be amd64 or arm64" ;; esac
[ -n "$VERSION" ] || VERSION=$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' "$ROOT/Cargo.toml" | head -1)
[ -n "$VERSION" ] || die "cannot read the version from Cargo.toml"
[ -d "$ROOT/share/skills" ] || die "$ROOT/share/skills is missing; run from a full checkout"
EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}
export SOURCE_DATE_EPOCH=$EPOCH

mkdir -p "$OUT"; OUT=$(cd -- "$OUT" && pwd); BIN=$(cd -- "$(dirname -- "$BIN")" && pwd)/$(basename -- "$BIN")
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/seagent-pkgstage.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

S=$STAGE/usr/share/seagent
mkdir -p "$S" "$STAGE/usr/share/doc/seagent" "$STAGE/usr/lib/systemd/system" "$STAGE/usr/lib/sysusers.d" "$STAGE/usr/lib/tmpfiles.d" "$STAGE/scripts"
cp -R "$ROOT/share/." "$S/"
mkdir -p "$S/vm" "$S/sandbox-browser" "$S/systemd" "$S/examples"
install -m 0755 "$ROOT/packaging/vm/build-image.sh" "$S/vm/build-image.sh"
install -m 0644 "$ROOT/packaging/vm/README.md" "$S/vm/README.md"
cp -R "$ROOT/packaging/sandbox-browser/." "$S/sandbox-browser/"
cp "$ROOT"/packaging/systemd/* "$S/systemd/"
install -m 0644 "$HERE/managed.toml.example" "$S/examples/managed.toml"
: > "$S/managed-by-package"          # `seagent update` leaves package-managed installs to the package manager
echo "linux-$ARCH" > "$S/TARGET"
for f in README.md LICENSE THIRD_PARTY_NOTICES.md; do [ -f "$ROOT/$f" ] && install -m 0644 "$ROOT/$f" "$STAGE/usr/share/doc/seagent/$f"; done
install -m 0644 "$ROOT/packaging/systemd/seagentd-system.service" "$STAGE/usr/lib/systemd/system/seagentd.service"
install -m 0644 "$ROOT/packaging/systemd/seagent-sysusers.conf" "$STAGE/usr/lib/sysusers.d/seagent.conf"
install -m 0644 "$ROOT/packaging/systemd/seagent-tmpfiles.conf" "$STAGE/usr/lib/tmpfiles.d/seagent.conf"
install -m 0755 "$HERE"/scripts/*.sh "$STAGE/scripts/"
mkdir -p "$STAGE/etc/init.d" && install -m 0755 "$ROOT/packaging/openrc/seagentd.initd" "$STAGE/etc/init.d/seagentd"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f ! -perm -u+x -exec chmod 0644 {} +
# a clean mtime so the packages do not depend on when the checkout happened
find "$STAGE" -exec touch -h -d "@$EPOCH" {} +

export VERSION ARCH
run_nfpm() { # run_nfpm <packager> <outfile-or-dir>
    local packager=$1
    if [ -n "$NFPM_CMD" ] || command -v nfpm >/dev/null 2>&1; then
        ( cd "$STAGE" && SEAGENT_BIN=$BIN STAGE=$STAGE ${NFPM_CMD:-nfpm} package -f "$HERE/nfpm.yaml" -p "$packager" -t "$OUT" )
        return
    fi
    local rt; rt=$(command -v podman || command -v docker) || die "need nfpm, podman or docker"
    local name="seagent-pkg-nfpm-$$-$packager"
    "$rt" run --rm --name "$name" -e VERSION -e ARCH -e SOURCE_DATE_EPOCH -e SEAGENT_BIN=/in/bin -e STAGE=/stage \
        -w /stage -v "$BIN:/in/bin:ro" -v "$STAGE:/stage:ro" -v "$HERE/nfpm.yaml:/nfpm.yaml:ro" -v "$OUT:/out" \
        docker.io/goreleaser/nfpm:latest package -f /nfpm.yaml -p "$packager" -t /out
}
run_nfpm deb
run_nfpm rpm
run_nfpm archlinux       # pacman: seagent-<ver>-1-x86_64.pkg.tar.zst
run_nfpm apk             # Alpine: seagent_<ver>-r1_x86_64.apk (OpenRC service included)
ls -l "$OUT"/seagent*.deb "$OUT"/seagent*.rpm "$OUT"/seagent*.pkg.tar.zst "$OUT"/seagent*.apk
