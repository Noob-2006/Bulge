#!/usr/bin/env bash
# Assert a release binary is what its target triple promises.
#
#   check-binary.sh <triple> <binary> [--max-glibc 2.28]
#
# *-musl : statically linked (no PT_INTERP, no DT_NEEDED) so it runs on any Linux, Alpine included.
# *-gnu  : dynamically linked, and no symbol version newer than GLIBC_<max> (default 2.28),
#          so it starts on RHEL 8 / Debian 10 / Ubuntu 18.04 and newer.
# Both   : the ELF machine matches the triple (x86_64 / aarch64).
# Needs readelf (binutils). Exit 0 = ok, 1 = violation, 2 = usage / missing tool.
set -euo pipefail
export LC_ALL=C
PROG=$(basename "$0")
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

[ $# -ge 2 ] || { echo "usage: $PROG <triple> <binary> [--max-glibc X.Y]" >&2; exit 2; }
TRIPLE=$1 BIN=$2
shift 2
MAX=2.28
while [ $# -gt 0 ]; do
    case "$1" in
        --max-glibc) MAX=${2:?}; shift ;;
        *) echo "$PROG: unknown option $1" >&2; exit 2 ;;
    esac
    shift
done
command -v readelf >/dev/null || { echo "$PROG: readelf (binutils) is required" >&2; exit 2; }
[ -f "$BIN" ] || die "no such file: $BIN"

hdr=$(readelf -hW "$BIN" 2>/dev/null) || die "$BIN is not an ELF file"
machine=$(printf '%s\n' "$hdr" | sed -n 's/^ *Machine: *//p')
case "$TRIPLE" in
    x86_64-*)  want='Advanced Micro Devices X86-64' ;;
    aarch64-*) want='AArch64' ;;
    *) die "unsupported triple $TRIPLE" ;;
esac
[ "$machine" = "$want" ] || die "$BIN is built for '$machine', expected '$want' ($TRIPLE)"

has_interp=0; readelf -lW "$BIN" | grep -q 'INTERP' && has_interp=1
needed=$(readelf -dW "$BIN" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')

case "$TRIPLE" in
    *-musl)
        [ "$has_interp" = 0 ] || die "$TRIPLE binary has a dynamic loader (PT_INTERP): not static"
        [ -z "$needed" ] || die "$TRIPLE binary needs shared libraries: $needed"
        echo "$PROG: $BIN is static ($TRIPLE)"
        ;;
    *-gnu)
        [ "$has_interp" = 1 ] || die "$TRIPLE binary is static; the gnu build is meant to be dynamic"
        newest=$( { readelf --version-info -W "$BIN" 2>/dev/null; readelf --dyn-syms -W "$BIN" 2>/dev/null; } \
            | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -t. -k1,1n -k2,2n -k3,3n -u | tail -n 1)
        if [ -n "$newest" ]; then
            top=$(printf '%s\n%s\n' "$newest" "$MAX" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
            [ "$top" = "$MAX" ] || die "$BIN needs GLIBC_$newest, newer than the GLIBC_$MAX floor"
        fi
        echo "$PROG: $BIN needs at most GLIBC_${newest:-none} (floor $MAX, $TRIPLE)"
        ;;
    *) die "unsupported triple $TRIPLE" ;;
esac
