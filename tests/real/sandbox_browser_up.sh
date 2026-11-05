#!/usr/bin/env bash
# Build (and verify) the sandbox-browser image the `sandbox` backend drives, then print
# the environment `crates/seagent-browser/tests/real_sandbox_browser.rs` needs.
#
#   eval "$(./tests/real/sandbox_browser_up.sh)"            # build if missing, print env
#   eval "$(./tests/real/sandbox_browser_up.sh --rebuild)"  # force a rebuild first
#   ./tests/real/sandbox_browser_up.sh --down               # remove the image again
#
# The image is `packaging/sandbox-browser` (Debian + Chromium + Xvfb + x11vnc + noVNC +
# the authenticated CDP relay). Nothing else is built or touched, and no container is
# left behind: the test starts and removes its own (`seagent-sbx-browser-*`).
#
# Container CLI: $SEAGENT_DOCKER, else docker, else podman (same resolution as seagent itself).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="seagent-sandbox-browser:trixie-slim"
CONTRACT=2026-11-cdp-relay-auth

REBUILD=0
DOWN=0
for a in "$@"; do
  case "$a" in
    --rebuild) REBUILD=1 ;;
    --down) DOWN=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown flag $a" >&2; exit 2 ;;
  esac
done

cli() {
  if [ -n "${SEAGENT_DOCKER:-}" ]; then printf '%s\n' "$SEAGENT_DOCKER"
  elif command -v docker >/dev/null 2>&1; then printf 'docker\n'
  elif command -v podman >/dev/null 2>&1; then printf 'podman\n'
  else echo "no container CLI: install docker or podman, or set SEAGENT_DOCKER" >&2; return 1; fi
}
CLI=$(cli) || exit 1

if [ "$DOWN" -eq 1 ]; then
  "$CLI" image rm -f "$IMAGE" >/dev/null 2>&1 || true
  echo "removed image $IMAGE (rebuild with: $0)" >&2
  exit 0
fi

have_image() {
  "$CLI" image inspect "$IMAGE" >/dev/null 2>&1
}

if [ "$REBUILD" -eq 1 ] || ! have_image; then
  echo "building $IMAGE with $CLI (Debian trixie + chromium, ~1-2 min the first time)..." >&2
  # --network=host so the build works behind the containers.conf default that blocks
  # outbound DNS in some rootless setups; only the package mirror is contacted.
  "$CLI" build --network=host -t "$IMAGE" "$ROOT/packaging/sandbox-browser" >&2
fi

label=$("$CLI" image inspect --format '{{index .Config.Labels "org.seagent.sandbox-browser.contract"}}' "$IMAGE")
if [ "$label" != "$CONTRACT" ]; then
  echo "image $IMAGE has contract label '$label', seagent expects '$CONTRACT' — rebuild it: $0 --rebuild" >&2
  exit 1
fi

printf 'export SEAGENT_REAL_SANDBOX_IMAGE=%s\n' "$IMAGE"
printf 'export SEAGENT_DOCKER=%s\n' "$CLI"
