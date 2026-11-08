#!/usr/bin/env bash
# Copy the installers Tauri produced for a target into dist/ with release-friendly names
# (no spaces: GitHub would rename them and break the updater URLs in latest.json).
#
#   apps/desktop/scripts/collect-bundles.sh <triple> [dist-dir]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app="$(cd "$here/.." && pwd)"
triple="$1"
dist="${2:-$app/dist}"
bundle="$app/target/$triple/release/bundle"
mkdir -p "$dist"
shopt -s nullglob
n=0
for f in "$bundle"/nsis/*.exe "$bundle"/nsis/*.exe.sig "$bundle"/msi/*.msi "$bundle"/msi/*.msi.sig \
         "$bundle"/dmg/*.dmg "$bundle"/macos/*.app.tar.gz "$bundle"/macos/*.app.tar.gz.sig \
         "$bundle"/appimage/*.AppImage "$bundle"/appimage/*.AppImage.sig "$bundle"/deb/*.deb "$bundle"/rpm/*.rpm; do
  name="$(basename "$f" | tr ' ' '-')"
  case "$name" in
    *.app.tar.gz|*.app.tar.gz.sig) name="${name/.app.tar.gz/_${triple}.app.tar.gz}" ;;
  esac
  cp "$f" "$dist/$name"
  n=$((n + 1))
done
# The macOS .app itself (zipped, for a quick look without mounting the dmg).
for a in "$bundle"/macos/*.app; do
  (cd "$(dirname "$a")" && ditto -c -k --keepParent "$(basename "$a")" "$dist/$(basename "$a" .app | tr ' ' '-')_${triple}.app.zip") && n=$((n + 1))
done
[[ $n -gt 0 ]] || { echo "no bundles found in $bundle" >&2; exit 1; }
ls -l "$dist"
