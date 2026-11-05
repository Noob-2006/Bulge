#!/usr/bin/env bash
# Verify a downloaded ark release directory, offline, without touching $HOME.
#
# What a downloader needs to be sure of, in the order that makes the other checks meaningful:
#   1. the detached Ed25519 signature over SHA256SUMS  — proves the checksum list is ours;
#   2. every file in SHA256SUMS really hashes to the listed value — proves the bytes are ours;
#   3. nothing else is in the directory — a stray file next to a signed release is either an
#      accident or an attempt to smuggle something in, and either way it is not covered;
#   4. the SBOM, if shipped, is a valid SPDX document — the inventory is part of the release.
#
# The order matters: checking hashes before the signature only proves the files match whatever
# list the attacker shipped alongside them.
#
# Usage: verify-release.sh <dir> [--key release-key.pub.pem]
set -euo pipefail

# Byte order, not locale order: `comm` and `sort` must agree, and a release that verifies
# differently on a zh_TW.UTF-8 machine is a bug.
export LC_ALL=C

PROG=$(basename "$0")
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DIR=
KEY=
KEY_FROM=

usage() {
    cat <<EOF
Usage: $PROG <dir> [--key FILE]

Verify a downloaded release directory:

  1. <dir>/SHA256SUMS.sig is a valid Ed25519 signature over <dir>/SHA256SUMS
  2. every line of SHA256SUMS matches the file it names
  3. every file in <dir> is listed in SHA256SUMS (SHA256SUMS and SHA256SUMS.sig excepted)
  4. any *.spdx.json SBOM in <dir> parses as SPDX 2.3

Options:
  --key FILE   public key to verify with (default: <dir>/release-key.pub.pem)
  --help       show this help

Pass --key with a key you obtained independently whenever you can: a key that arrives in the
same download as the signature protects against corruption, not against a compromised host.
Runs fully offline; scratch files go to \$TMPDIR, never \$HOME.
EOF
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

[ $# -ge 1 ] || { usage >&2; exit 2; }
case "$1" in --help|-h) usage; exit 0 ;; esac
DIR=$1; shift
while [ $# -gt 0 ]; do
    case "$1" in
        --key) [ $# -ge 2 ] || die "--key needs a value"; KEY=$2; KEY_FROM=flag; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -d "$DIR" ] || die "$DIR: not a directory"
DIR=$(cd -- "$DIR" && pwd)

SUMS=$DIR/SHA256SUMS
SIG=$SUMS.sig
[ -f "$SUMS" ] || die "$SUMS: missing — is this really a release directory?"
[ -f "$SIG" ] || die "$SIG: missing detached signature"
if [ -z "$KEY" ]; then
    KEY=$DIR/release-key.pub.pem
    KEY_FROM=dir
fi
[ -f "$KEY" ] || die "$KEY: public key not found (pass --key FILE)"

command -v openssl >/dev/null 2>&1 || die "openssl not found in PATH"

FAILS=0
pass() { printf '  [PASS] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }

# `sha256sum` is coreutils; `shasum -a 256` is the Perl fallback some images carry instead.
if command -v sha256sum >/dev/null 2>&1; then
    SHA256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    SHA256=(shasum -a 256)
else
    die "neither sha256sum nor shasum found in PATH"
fi

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/ark-verify-XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT

printf '%s: verifying %s\n' "$PROG" "$DIR"

# --- (a) signature -------------------------------------------------------------------------
if base64 -d < "$SIG" > "$SCRATCH/sig.bin" 2>/dev/null \
        || base64 -D < "$SIG" > "$SCRATCH/sig.bin" 2>/dev/null; then
    if openssl pkeyutl -verify -pubin -rawin -inkey "$KEY" -in "$SUMS" \
            -sigfile "$SCRATCH/sig.bin" >/dev/null 2>&1; then
        pass "signature over SHA256SUMS ($(basename -- "$KEY"), ed25519)"
    else
        fail "signature over SHA256SUMS does not verify against $(basename -- "$KEY")"
    fi
else
    fail "SHA256SUMS.sig is not valid base64"
fi
if [ "$KEY_FROM" = dir ]; then
    printf '  [NOTE] key came from the release directory itself; re-run with --key <trusted file> to rule out a swapped key\n'
fi

# --- (b) per-file checksums ----------------------------------------------------------------
CHECK_OUT=$SCRATCH/check.out
if ( cd "$DIR" && "${SHA256[@]}" --check --strict SHA256SUMS > "$CHECK_OUT" 2>&1 ); then
    COUNT=$(grep -c ': OK$' "$CHECK_OUT" || true)
    pass "all $COUNT listed file(s) match SHA256SUMS"
else
    fail "checksum mismatch:"
    grep -v ': OK$' "$CHECK_OUT" | sed 's/^/         /' >&2 || true
fi

# --- (c) no unlisted files -----------------------------------------------------------------
# SHA256SUMS cannot contain its own hash (or its signature's), so those two are expected extras.
LISTED=$SCRATCH/listed.txt
PRESENT=$SCRATCH/present.txt
awk '{ sub(/^[0-9a-fA-F]+ [ *]/, ""); print }' "$SUMS" | sed 's|^\./||' | sort -u > "$LISTED"
( cd "$DIR" && find . -type f | sed 's|^\./||' ) | sort -u > "$PRESENT"

EXTRA=$SCRATCH/extra.txt
comm -13 "$LISTED" "$PRESENT" | grep -v -x -e 'SHA256SUMS' -e 'SHA256SUMS.sig' > "$EXTRA" || true
if [ -s "$EXTRA" ]; then
    fail "file(s) present but not listed in SHA256SUMS:"
    sed 's/^/         /' "$EXTRA" >&2
else
    pass "no unlisted files in the release directory"
fi

MISSING=$SCRATCH/missing.txt
comm -23 "$LISTED" "$PRESENT" > "$MISSING" || true
if [ -s "$MISSING" ]; then
    fail "SHA256SUMS lists file(s) that are not in the directory:"
    sed 's/^/         /' "$MISSING" >&2
fi

# --- (d) SBOM ------------------------------------------------------------------------------
SBOM=
for candidate in "$DIR"/sbom.spdx.json "$DIR"/*.spdx.json; do
    if [ -f "$candidate" ]; then SBOM=$candidate; break; fi
done
if [ -n "$SBOM" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
        fail "$(basename -- "$SBOM"): python3 is required to validate the SBOM"
    elif python3 "$SCRIPT_DIR/sbom.py" --check --out "$SBOM" > "$SCRATCH/sbom.out" 2>&1; then
        pass "$(basename -- "$SBOM") is a valid SPDX 2.3 document"
    else
        fail "$(basename -- "$SBOM") is not a valid SPDX document:"
        sed 's/^/         /' "$SCRATCH/sbom.out" >&2
    fi
else
    printf '  [SKIP] no SBOM (*.spdx.json) in the directory\n'
fi

if [ "$FAILS" -ne 0 ]; then
    printf '%s: FAILED (%d check(s))\n' "$PROG" "$FAILS" >&2
    exit 1
fi
printf '%s: OK — %s verifies\n' "$PROG" "$DIR"
