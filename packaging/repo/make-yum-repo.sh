#!/usr/bin/env bash
# Signed yum/dnf repository from .rpm files (ent-027).
#
#   make-yum-repo.sh --rpms DIR --out REPO --key-id KEYID [--gnupghome DIR] [--passphrase-file F]
#                    [--base-url URL] [--container]
#
# Needs createrepo_c, rpmsign (rpm-sign) and gpg. With --container (or when those tools are
# missing and podman/docker exists) the work happens in a docker.io/library/rockylinux:9 container
# named seagent-pkg-yum-*; your GNUPGHOME is mounted read-only.
# Result:
#   REPO/<arch>/*.rpm                   each signed (rpm header signature, checked by gpgcheck=1)
#   REPO/<arch>/repodata/repomd.xml{,.asc}   metadata signed too (repo_gpgcheck=1)
#   REPO/RPM-GPG-KEY-seagent           the public key
#   REPO/seagent.repo                  drop-in for /etc/yum.repos.d/
set -euo pipefail
PROG=$(basename "$0")
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
RPMS="" OUT="" KEY="" GNUPGHOME_ARG="" PASSFILE="" BASE_URL="https://packages.example.com/seagent/rpm" USE_CONTAINER=0 INNER=0
while [ $# -gt 0 ]; do
    case "$1" in
        --rpms) RPMS=${2:?}; shift ;;
        --out) OUT=${2:?}; shift ;;
        --key-id) KEY=${2:?}; shift ;;
        --gnupghome) GNUPGHOME_ARG=${2:?}; shift ;;
        --passphrase-file) PASSFILE=${2:?}; shift ;;
        --base-url) BASE_URL=${2:?}; shift ;;
        --container) USE_CONTAINER=1 ;;
        --inner) INNER=1 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
    shift
done
[ -d "$RPMS" ] && [ -n "$OUT" ] && [ -n "$KEY" ] || die "usage: $PROG --rpms DIR --out REPO --key-id KEYID [--gnupghome DIR]"
GNUPGHOME_ARG=${GNUPGHOME_ARG:-${GNUPGHOME:-$HOME/.gnupg}}

if [ "$INNER" = 0 ] && { [ "$USE_CONTAINER" = 1 ] || ! { command -v createrepo_c && command -v rpmsign; } >/dev/null 2>&1; }; then
    rt=$(command -v podman || command -v docker) || die "need createrepo_c+rpmsign, or podman/docker"
    mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd); RPMS=$(cd "$RPMS" && pwd)
    HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    extra=()
    [ -n "$PASSFILE" ] && extra+=(-v "$(cd "$(dirname "$PASSFILE")" && pwd)/$(basename "$PASSFILE"):/pass:ro" --passphrase-file /pass)
    # the gnupg home is copied: gpg writes lock/socket files, and the original must stay untouched
    exec "$rt" run --rm --name "seagent-pkg-yum-$$" -v "$RPMS:/rpms:ro" -v "$OUT:/out" -v "$GNUPGHOME_ARG:/gnupg-src:ro" \
        -v "$HERE/make-yum-repo.sh:/make-yum-repo.sh:ro" docker.io/library/rockylinux:9 \
        bash -c 'dnf -y -q install createrepo_c rpm-sign gnupg2 >/dev/null && umask 077 && mkdir /gnupg && cp -a /gnupg-src/. /gnupg/ && rm -f /gnupg/S.* /gnupg/*.lock && exec bash /make-yum-repo.sh --inner "$@"' \
        _ --rpms /rpms --out /out --key-id "$KEY" --gnupghome /gnupg --base-url "$BASE_URL" ${extra[@]+"${extra[@]}"}
fi

export GNUPGHOME=$GNUPGHOME_ARG
GPG=(gpg --batch --yes --no-tty --local-user "$KEY")
[ -n "$PASSFILE" ] && GPG+=(--pinentry-mode loopback --passphrase-file "$PASSFILE")
mkdir -p "$OUT"
# rpm signing uses a gpg command line of its own; make it non-interactive.
SIGN_CMD="%{__gpg} gpg --batch --no-tty --no-verbose --no-armor --pinentry-mode loopback ${PASSFILE:+--passphrase-file $PASSFILE} --no-secmem-warning -u \"%{_gpg_name}\" -sbo %{__signature_filename} --digest-algo sha256 %{__plaintext_filename}"
gpg --batch --armor --export "$KEY" > "$OUT/RPM-GPG-KEY-seagent"
n=0
# One repository per architecture, matching baseurl=…/$basearch in seagent.repo.
for arch in $(ls "$RPMS" | sed -n 's/.*\.\([A-Za-z0-9_]*\)\.rpm$/\1/p' | sort -u); do
    d="$OUT/$arch"
    rm -rf "$d/repodata"; mkdir -p "$d"
    cp "$RPMS"/*."$arch".rpm "$d"/
    for r in "$d"/*.rpm; do
        rpmsign --define "_gpg_name $KEY" --define "__gpg_sign_cmd $SIGN_CMD" --addsign "$r" >/dev/null
        n=$((n + 1))
    done
    # gz metadata: readable by the old yum/rpm of EL7 as well
    createrepo_c --quiet --general-compress-type gz "$d"
    "${GPG[@]}" --armor --detach-sign --output "$d/repodata/repomd.xml.asc" "$d/repodata/repomd.xml"
done
[ "$n" -gt 0 ] || die "no .rpm files in $RPMS"
cat > "$OUT/seagent.repo" <<REPO
[seagent]
name=seagent agent runtime
baseurl=$BASE_URL/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$BASE_URL/RPM-GPG-KEY-seagent
REPO
echo "yum repository: $OUT ($n package(s)); client: curl -O $BASE_URL/seagent.repo → /etc/yum.repos.d/"
