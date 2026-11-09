#!/usr/bin/env bash
# Before `cargo tauri ios build|dev`: put the WASI tool set into the app bundle.
#
#   apps/desktop/scripts/prepare-ios.sh [--rebuild]
#
# The iOS app runs the agent in-process (no child processes on iOS) and its commands as WASI
# modules in the wasmi interpreter. tauri.ios.conf.json bundles
#   ../../../share/  → share/        (skills, roles, catalogs — SEAGENT_SHARE_DIR)
#   wasi-tools/      → share/wasi/   (coreutils, sed, find, grep, CPython + tools.json with pinned SHA-256s)
# This script makes sure src-tauri/wasi-tools is complete and verifies it; `--rebuild` rebuilds
# it with build-wasi-tools.sh and build-wasi-python.sh (pinned sources and wasi-sdk).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app="$(cd "$here/.." && pwd)"
tools="$app/src-tauri/wasi-tools"

if [[ "${1:-}" == "--rebuild" || ! -f "$tools/tools.json" ]]; then
  "$here/build-wasi-tools.sh" "$tools"
  "$here/build-wasi-python.sh" "$tools"
elif [[ ! -f "$tools/python.wasm" ]]; then
  "$here/build-wasi-python.sh" "$tools"
fi
"$here/build-wasi-tools.sh" --check "$tools"
echo "ios: WASI tools ready in $tools ($(du -sh "$tools" | cut -f1)); bundled as share/wasi"
