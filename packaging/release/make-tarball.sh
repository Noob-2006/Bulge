#!/usr/bin/env bash
# Assemble one release tarball: the binary plus everything seagent needs at run time.
#
#   make-tarball.sh <triple> <seagent-binary> <out.tar.gz> [--vm-agent PATH]
#
# Layout (a prefix, so `tar -xzf … -C ~/.local` and `-C /usr/local` both work):
#   bin/seagent
#   share/seagent/{skills,optional-skills,optional-mcps,plugin-catalog,roles,blueprints.json}
#   share/seagent/vm/{build-image.sh,mkdisk.py,kernel/,README.md[,seagent-vm-guest]}     microVM guest image builder
#   share/seagent/sandbox-browser/…                                sandbox-browser image sources
#   share/seagent/systemd/{seagentd.service,seagentd-system.service,…}     generated units, sysusers, tmpfiles
#   share/doc/seagent/{README.md,THIRD_PARTY_NOTICES.md}
# `seagent` finds share/seagent at run time through <exe>/../share/seagent (see seagent_core::share).
#
# Deterministic: sorted entries, fixed owner/mtime (SOURCE_DATE_EPOCH, default = HEAD commit
# time), `gzip -n`. Same inputs, same bytes.
set -euo pipefail
export LC_ALL=C

PROG=$(basename "$0")
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

[ $# -ge 3 ] || die "usage: $PROG <triple> <seagent-binary> <out.tar.gz> [--vm-agent PATH]"
TRIPLE=$1 BIN=$2 OUT=$3
shift 3
AGENT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --vm-agent) AGENT=${2:?--vm-agent needs a path}; shift ;;
        *) die "unknown option $1" ;;
    esac
    shift
done
[ -f "$BIN" ] || die "no such binary: $BIN"
[ -d "$ROOT/share/skills" ] || die "$ROOT/share/skills is missing; run from a full checkout"

EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/seagent-tarball.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

install -D -m 0755 "$BIN" "$STAGE/bin/seagent"
S=$STAGE/share/seagent
mkdir -p "$S" "$STAGE/share/doc/seagent"
cp -R "$ROOT/share/." "$S/"
mkdir -p "$S/vm" "$S/sandbox-browser" "$S/systemd"
install -m 0755 "$ROOT/packaging/vm/build-image.sh" "$S/vm/build-image.sh"
install -m 0644 "$ROOT/packaging/vm/README.md" "$S/vm/README.md"
install -m 0755 "$ROOT/packaging/vm/mkdisk.py" "$S/vm/mkdisk.py"
mkdir -p "$S/vm/kernel" && install -m 0644 "$ROOT"/packaging/vm/kernel/*.config "$S/vm/kernel/"
if [ -n "$AGENT" ]; then
    [ -f "$AGENT" ] || die "no such vm agent: $AGENT"
    install -m 0755 "$AGENT" "$S/vm/seagent-vm-guest"
fi
cp -R "$ROOT/packaging/sandbox-browser/." "$S/sandbox-browser/"
cp "$ROOT"/packaging/systemd/* "$S/systemd/"
for f in README.md LICENSE THIRD_PARTY_NOTICES.md; do
    [ -f "$ROOT/$f" ] && install -m 0644 "$ROOT/$f" "$STAGE/share/doc/seagent/$f"
done
echo "$TRIPLE" > "$S/TARGET"
# Normalise modes: dirs 755, files 644 unless executable already.
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f ! -perm -u+x -exec chmod 0644 {} +

OUT_ABS=$(cd -- "$(dirname -- "$OUT")" && pwd)/$(basename -- "$OUT")
( cd "$STAGE" && tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner --format=gnu -cf - . | gzip -n -9 > "$OUT_ABS" )
echo "$OUT_ABS"
