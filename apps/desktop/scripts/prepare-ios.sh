#!/usr/bin/env bash
# Before `cargo tauri ios build|dev`: put the WASI tool set into the app bundle.
#
#   apps/desktop/scripts/prepare-ios.sh [--rebuild]
#
# The iOS app runs the agent in-process (no child processes on iOS) and its commands as WASI
# modules in the wasmi interpreter. tauri.ios.conf.json bundles
#   ../../../share/  → share/        (skills, roles, catalogs — SEAGENT_SHARE_DIR)
#   wasi-tools/      → share/wasi/   (coreutils.wasm + tools.json with pinned SHA-256s)
# This script makes sure src-tauri/wasi-tools exists and verifies it; `--rebuild` rebuilds it
# with build-wasi-tools.sh (pinned uutils coreutils, pure Rust, no wasi-sdk needed).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app="$(cd "$here/.." && pwd)"
tools="$app/src-tauri/wasi-tools"

if [[ "${1:-}" == "--rebuild" || ! -f "$tools/tools.json" ]]; then
  "$here/build-wasi-tools.sh" "$tools"
else
  "$here/build-wasi-tools.sh" --check "$tools"
fi
echo "ios: WASI tools ready in $tools ($(du -sh "$tools" | cut -f1)); bundled as share/wasi"
