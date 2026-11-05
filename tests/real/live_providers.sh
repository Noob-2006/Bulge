#!/usr/bin/env bash
# Live provider smoke tests (gen1-307): one real request per web-search provider and one
# TTS→STT round trip per media provider, for every provider whose key is in the environment.
# Costs real (small) API usage, so it never runs by default and is not part of realtest.sh.
#
#   BRAVE_API_KEY=… OPENAI_API_KEY=… tests/real/live_providers.sh
#
# Keys are read from the environment only (never written anywhere); providers without a key
# report SKIPPED. Exit status is non-zero if any provider that had a key failed.
set -uo pipefail
cd "$(dirname "$0")/../.."
export ARK_LIVE_PROVIDERS=1 ARK_OFFLINE=1
rc=0
log=$(mktemp "${TMPDIR:-/tmp}/ark-live-XXXX")
trap 'rm -f "$log"' EXIT
for t in "ark-tools live_web_providers" "ark-media live_media_providers"; do
  set -- $t
  cargo test -p "$1" --test "$2" -- --ignored --test-threads=1 --nocapture >"$log" 2>&1 || rc=1
  grep -E '^test |SKIPPED|: ok|→|panicked|^test result' "$log"
done
exit $rc
