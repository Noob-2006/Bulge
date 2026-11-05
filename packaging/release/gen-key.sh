#!/usr/bin/env bash
# Create the Ed25519 release signing keypair with `openssl` only.
#
# Why Ed25519: signatures are 64 bytes (so `SHA256SUMS.sig` stays a short base64 line),
# verification is deterministic and fast, and OpenSSL 3.x signs raw messages with
# `pkeyutl -rawin`, so neither the release build nor the person verifying a download needs
# anything beyond openssl. No new crate, no PGP, no key server.
#
# Custody: the private key is written 0600 in the current directory by default and must never be
# committed, copied to CI logs, or stored next to the artifacts. Only `release-key.pub.pem` is
# published. Losing the key means re-issuing it and re-signing every past release, so keep a
# backup offline; leaking it means every signature ever made with it is worthless.
#
# Usage: gen-key.sh [--out-dir DIR] [--force]
set -euo pipefail

# Byte order, not locale order: `comm` and `sort` must agree, and a release that verifies
# differently on a zh_TW.UTF-8 machine is a bug.
export LC_ALL=C

PROG=$(basename "$0")
OUT_DIR=.
FORCE=0
PRIV_NAME=release-key.pem
PUB_NAME=release-key.pub.pem

usage() {
    cat <<EOF
Usage: $PROG [--out-dir DIR] [--force]

Create an Ed25519 release keypair in DIR (default: current directory):
  $PRIV_NAME       private key, mode 0600 — NEVER commit or publish this
  $PUB_NAME        public key, published next to the artifacts

Options:
  --out-dir DIR   where to write the keypair (created if missing)
  --force         overwrite an existing keypair (destroys the old private key)
  --help          show this help

Requires: openssl 3.x (ed25519 + \`pkeyutl -rawin\`).
EOF
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out-dir) [ $# -ge 2 ] || die "--out-dir needs a value"; OUT_DIR=$2; shift 2 ;;
        --force) FORCE=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

command -v openssl >/dev/null 2>&1 || die "openssl not found in PATH"

mkdir -p "$OUT_DIR"
PRIV=$OUT_DIR/$PRIV_NAME
PUB=$OUT_DIR/$PUB_NAME

if [ -e "$PRIV" ] && [ "$FORCE" -ne 1 ]; then
    die "$PRIV already exists — refusing to overwrite the private key (use --force if you really mean it)"
fi

# 077 first so the private key is never world-readable, not even for the moment between
# `genpkey` creating it and a later `chmod`.
umask 077
openssl genpkey -algorithm ed25519 -out "$PRIV"
chmod 600 "$PRIV"

# The public half is derived, not stored: this also proves the private key parses.
openssl pkey -in "$PRIV" -pubout -out "$PUB"
chmod 644 "$PUB"

cat >&2 <<EOF

$PROG: wrote
  $PRIV   (0600, private)
  $PUB   (public)

  WARNING: $PRIV must NEVER be committed, uploaded, pasted into a ticket or kept on the
  release machine. Store it offline (password manager / hardware token), keep a backup, and
  publish only $PUB_NAME. Anyone holding it can sign a release that looks official.

  Publish the public key, then sign a release checksum file with:
    packaging/release/sign.sh dist/SHA256SUMS $PRIV
EOF
