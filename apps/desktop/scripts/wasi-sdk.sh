#!/usr/bin/env bash
# Sourced by build-wasi-tools.sh and build-wasi-python.sh: the pinned wasi-sdk (C toolchain for
# wasm32-wasip1) from the official WebAssembly/wasi-sdk GitHub release, SHA-256 checked.
#   source wasi-sdk.sh; sdk="$(wasi_sdk)"      → path of the unpacked SDK
# Version 24 is the one CPython 3.14's Tools/wasm/wasi supports.
WASI_SDK=24
# (a case, not an associative array: macOS still ships bash 3.2)
wasi_sdk_sha256() {
  case "$1" in
    x86_64-linux) echo c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5 ;;
    arm64-macos) echo aeae999396d5f5caa5ce419f52e83c35869d5fd21d40af80acba2c80f51b0b3a ;;
    x86_64-macos) echo 4bfc274ae8b68c771dd93e32ad4bd695336ca46b585beb3b1260e5602dbc11a2 ;;
  esac
}
SEAGENT_WASI_WORK="${SEAGENT_WASI_WORK:-$HOME/.cache/seagent-wasi}"

# fetch URL FILE SHA256 → $SEAGENT_WASI_WORK/dl/FILE, verified (a mismatch is deleted and fatal).
fetch_pinned() {
  mkdir -p "$SEAGENT_WASI_WORK/dl"
  local f="$SEAGENT_WASI_WORK/dl/$2" got
  if [[ ! -f "$f" ]]; then
    curl -sSfL "$1" -o "$f.part"
    mv "$f.part" "$f"
  fi
  got="$( (command -v sha256sum >/dev/null && sha256sum "$f" || shasum -a 256 "$f") | cut -d' ' -f1)"
  if [[ "$got" != "$3" ]]; then
    echo "$2 has SHA-256 $got, pinned $3 — refusing it" >&2
    rm -f "$f"
    return 1
  fi
}

wasi_sdk() {
  local host
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) host=x86_64-linux ;;
    Darwin-arm64) host=arm64-macos ;;
    Darwin-x86_64) host=x86_64-macos ;;
    *) echo "no pinned wasi-sdk for $(uname -s)-$(uname -m)" >&2; return 1 ;;
  esac
  local name="wasi-sdk-$WASI_SDK.0-$host"
  fetch_pinned "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-$WASI_SDK/$name.tar.gz" "$name.tar.gz" "$(wasi_sdk_sha256 "$host")" >&2 || return 1
  [[ -d "$SEAGENT_WASI_WORK/$name" ]] || tar -xzf "$SEAGENT_WASI_WORK/dl/$name.tar.gz" -C "$SEAGENT_WASI_WORK"
  echo "$SEAGENT_WASI_WORK/$name"
}
