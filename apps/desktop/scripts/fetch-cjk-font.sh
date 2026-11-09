#!/usr/bin/env bash
# Fetch the CJK font bundled into the Linux AppImage (only there: the .deb/.rpm Recommend the
# distro's Noto CJK package instead). Pinned to a commit of the official googlefonts/noto-cjk
# repository (tag Sans2.004) and checked against its SHA-256; nothing is committed to git
# (12 MB binary). Idempotent: a file that already matches is kept.
#
#   apps/desktop/scripts/fetch-cjk-font.sh      # → apps/desktop/src-tauri/fonts/NotoSansTC-VF.ttf
#
# Noto Sans TC variable font (Thin–Black, Traditional Chinese "Subset" build: TC + common SC/Latin),
# SIL OFL 1.1 — the license ships next to it (src-tauri/fonts/OFL.txt, committed).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="$here/../src-tauri/fonts"
commit=523d033d6cb47f4a80c58a35753646f5c3608a78   # googlefonts/noto-cjk tag Sans2.004
url="https://raw.githubusercontent.com/googlefonts/noto-cjk/$commit/Sans/Variable/TTF/Subset/NotoSansTC-VF.ttf"
sha=ac091cc8cd19e848202afc8fe6d3809b4526c8fdbdb4be82da20c4f785949591
out="$dir/NotoSansTC-VF.ttf"

have() { [[ -f "$out" ]] && echo "$sha  $out" | sha256sum -c --status; }
if have; then
  echo "cjk font: $out (cached, sha256 ok)"
  exit 0
fi
mkdir -p "$dir"
tmp="$(mktemp "$dir/.font.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp" "$url"
if ! echo "$sha  $tmp" | sha256sum -c --status; then
  echo "cjk font: SHA-256 mismatch for $url" >&2
  exit 1
fi
chmod 0644 "$tmp"   # mktemp creates 0600; the AppImage keeps file modes
mv "$tmp" "$out"
echo "cjk font: $out ($(du -h "$out" | cut -f1), sha256 ok)"
