#!/usr/bin/env bash
# Regenerate the app icons from ui/icon.svg.
#
#   apps/desktop/scripts/icons.sh            # desktop set (committed): pure-Python renderer
#   apps/desktop/scripts/icons.sh --tauri    # full set incl. Android/iOS via the Tauri CLI
#                                            # (cargo install tauri-cli --version '^2' --locked)
#
# Run after `cargo tauri android init` / `ios init` with --tauri so gen/android and gen/apple get
# their launcher icons too.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app="$here/.."
svg="$app/../../ui/icon.svg"

if [[ "${1:-}" == "--tauri" ]]; then
  cd "$app/src-tauri"
  cargo tauri icon "$svg" --output icons
else
  python3 "$here/icons.py" "$app/src-tauri/icons"
fi
