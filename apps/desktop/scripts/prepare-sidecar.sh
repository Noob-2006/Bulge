#!/usr/bin/env bash
# Build the agent (`seagent`, root workspace) for a target triple and put it where Tauri expects
# the sidecar: apps/desktop/src-tauri/binaries/seagent-<triple>[.exe] (bundle.externalBin).
#
#   apps/desktop/scripts/prepare-sidecar.sh                         # host triple
#   apps/desktop/scripts/prepare-sidecar.sh x86_64-pc-windows-msvc
#   apps/desktop/scripts/prepare-sidecar.sh universal-apple-darwin  # both macOS arches + lipo
#   SEAGENT_BIN=/path/to/seagent apps/desktop/scripts/prepare-sidecar.sh   # use a prebuilt binary
#
# PROFILE=debug for a quicker local build. Android does not use this (no sidecars on mobile):
# see scripts/prepare-android.sh.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
out="$root/apps/desktop/src-tauri/binaries"
host="$(rustc -vV | sed -n 's/^host: //p')"
triple="${1:-$host}"
profile="${PROFILE:-release}"
mkdir -p "$out"

ext=""
case "$triple" in *windows*) ext=".exe" ;; esac

build() {
  local t="$1"
  local flag="--release"; [[ "$profile" == debug ]] && flag=""
  (cd "$root" && cargo build $flag --locked -p seagent --bin seagent --target "$t") >&2
  echo "$root/target/$t/$profile/seagent$ext"
}

if [[ -n "${SEAGENT_BIN:-}" ]]; then
  cp "$SEAGENT_BIN" "$out/seagent-$triple$ext"
elif [[ "$triple" == universal-apple-darwin ]]; then
  a="$(build aarch64-apple-darwin)"
  x="$(build x86_64-apple-darwin)"
  lipo -create -output "$out/seagent-universal-apple-darwin" "$a" "$x"
  # `cargo tauri build --target universal-apple-darwin` also looks for the per-arch names.
  cp "$a" "$out/seagent-aarch64-apple-darwin"
  cp "$x" "$out/seagent-x86_64-apple-darwin"
else
  cp "$(build "$triple")" "$out/seagent-$triple$ext"
fi
chmod +x "$out"/seagent-* 2>/dev/null || true
# The Linux AppImage bundles a CJK font (bundle.linux.appimage.files): fetch it (pinned + sha256).
case "$triple" in *linux-gnu*) "$here/fetch-cjk-font.sh" ;; esac
# The Windows installers bundle the virtual display driver (resources vdd/, pinned + sha256).
case "$triple" in *windows*) "$here/fetch-vdd.sh" ;; esac
ls -l "$out"
