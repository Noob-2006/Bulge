#!/usr/bin/env bash
# Detached Ed25519 signature over a release `SHA256SUMS` file.
#
# Why sign the checksum file instead of every artifact: one signature covers the whole release,
# and it is the same file a user verifies first (`sha256sum -c`). The signature is base64 so it
# travels through GitHub releases, email and web pages unchanged; the raw bytes are useless in a
# text field.
#
# Why `pkeyutl -rawin`: OpenSSL 3 signs the message directly (Ed25519 is a "pure" signature
# scheme; hashing first would be wrong). `openssl dgst -sign` would need an intermediate hash.
#
# The private key is refused when group/world readable: a 0644 key silently makes every signature
# meaningless, and it is the single most common mistake in hand-rolled release flows.
#
# Usage: sign.sh <SHA256SUMS> <private-key.pem> [out.sig]
set -euo pipefail

# Byte order, not locale order: `comm` and `sort` must agree, and a release that verifies
# differently on a zh_TW.UTF-8 machine is a bug.
export LC_ALL=C

PROG=$(basename "$0")

usage() {
    cat <<EOF
Usage: $PROG <SHA256SUMS> <private-key.pem> [out.sig]

Sign the checksum file and write a detached base64 Ed25519 signature
(default: <SHA256SUMS>.sig). The signature is verified once right after writing it,
so a broken key setup fails here instead of at the downloader's end.

Options:
  --help   show this help

Key hygiene: the private key must be mode 0600 (or stricter); group/world
readable keys are refused. Generate one with \`gen-key.sh\`; publish only the
matching release-key.pub.pem.
EOF
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

[ $# -ge 1 ] || { usage >&2; exit 2; }
case "$1" in --help|-h) usage; exit 0 ;; esac
[ $# -ge 2 ] || die "need <SHA256SUMS> and <private-key.pem> (try --help)"

SUMS=$1
KEY=$2
OUT=${3:-$SUMS.sig}

command -v openssl >/dev/null 2>&1 || die "openssl not found in PATH"
[ -f "$SUMS" ] || die "$SUMS: no such file"
[ -s "$SUMS" ] || die "$SUMS: file is empty — signing nothing is worse than not signing"
[ -f "$KEY" ] || die "$KEY: no such file"
[ -r "$KEY" ] || die "$KEY: not readable"

# Mode 0640/0604/0666 all expose the private key to other local users.
MODE=$(stat -c '%a' "$KEY" 2>/dev/null || stat -f '%Lp' "$KEY" 2>/dev/null || echo "")
case "$MODE" in
    '') die "$KEY: cannot determine file mode (is stat available?)" ;;
esac
if [ $(( 8#$MODE & 8#077 )) -ne 0 ]; then
    die "$KEY has mode $MODE (group/world accessible) — chmod 600 $KEY before signing"
fi

# Refuse anything that is not an Ed25519 key: the verifier assumes that algorithm, and a silent
# RSA signature would fail at the other end with a confusing error.
KEY_TYPE=$(openssl pkey -in "$KEY" -noout -text 2>/dev/null | head -1 || true)
case "$KEY_TYPE" in
    *ED25519*) : ;;
    '') die "$KEY: openssl cannot read this key (encrypted keys are not supported here)" ;;
    *) die "$KEY is not an Ed25519 key (found: $KEY_TYPE) — run gen-key.sh" ;;
esac

# Scratch space for the self-check, under $TMPDIR, never $HOME.
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/ark-sign-XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT

sig_b64() {
    # `-rawin` signs the file content as-is; base64 -w0 keeps the .sig a single line so it can be
    # pasted into a release note. `tr` instead of `-w0` keeps BSD/macOS base64 working.
    openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$SUMS" | base64 | tr -d '\n'
}

SIG=$(sig_b64)
[ -n "$SIG" ] || die "openssl produced an empty signature"

printf '%s\n' "$SIG" > "$OUT"

# Self-check: extract the public half and verify what we just wrote. A signature that cannot be
# verified on the signing machine is not worth publishing, and failing now costs seconds.
openssl pkey -in "$KEY" -pubout -out "$SCRATCH/pub.pem" 2>/dev/null \
    || die "$KEY: cannot derive the public key"
printf '%s\n' "$SIG" | base64 -d > "$SCRATCH/sig.bin" 2>/dev/null \
    || die "internal: cannot decode the signature we just wrote"
if ! openssl pkeyutl -verify -pubin -rawin -inkey "$SCRATCH/pub.pem" \
        -in "$SUMS" -sigfile "$SCRATCH/sig.bin" >/dev/null 2>&1; then
    rm -f "$OUT"
    die "$KEY: the signature does not verify against its own public key — key file corrupt?"
fi

printf '%s: signed %s -> %s (%s bytes, ed25519, self-check OK)\n' \
    "$PROG" "$SUMS" "$OUT" "$(printf '%s' "$SIG" | base64 -d | wc -c | tr -d ' ')"
