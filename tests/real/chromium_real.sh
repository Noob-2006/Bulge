#!/usr/bin/env bash
# Real Chromium check for the browser layer (E3).
#
# What this proves: a real browser on this machine starts headless with the CDP
# flags ark's launcher uses (remote debugging on a loopback port, a throwaway
# profile), exposes the DevTools HTTP endpoints, executes page JavaScript, and
# renders a screenshot. What it does NOT prove: ark's CDP client driving that
# browser end to end (see docs/protocols/README.md, E3 section).
#
# Kills only the Chromium process it started; the profile lives under $TMPDIR.
set -euo pipefail

TMPDIR_REAL="${TMPDIR:-/tmp}/ark-browser-$$"
mkdir -p "$TMPDIR_REAL"
PROFILE="$TMPDIR_REAL/profile"
PORT="${ARK_BROWSER_PORT:-29333}"
URL="data:text/html,<html><body><h1 id=h>before</h1><script>document.getElementById('h').textContent='ark-js-ok'</script></body></html>"

CHROME=""
for c in "${CHROME_PATH:-}" /usr/bin/google-chrome-stable /usr/bin/google-chrome /usr/bin/chromium /snap/bin/chromium /usr/bin/chromium-browser; do
  [ -n "$c" ] && [ -x "$c" ] && CHROME=$c && break
done
[ -n "$CHROME" ] || { echo "no chromium found; set CHROME_PATH" >&2; exit 1; }

PID=""
cleanup() {
  local rc=$?
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  [ -n "$PID" ] && wait "$PID" 2>/dev/null || true
  rm -rf "$TMPDIR_REAL"
  exit $rc
}
trap cleanup EXIT INT TERM

echo "browser: $CHROME"
"$CHROME" --version

# Same shape as ark's launcher: loopback DevTools port, isolated profile, headless.
"$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
  --user-data-dir="$PROFILE" --remote-debugging-port="$PORT" --remote-debugging-address=127.0.0.1 \
  about:blank >"$TMPDIR_REAL/chrome.log" 2>&1 &
PID=$!
started=$SECONDS
while [ $((SECONDS - started)) -lt 30 ]; do
  if curl -sf -m 2 "http://127.0.0.1:$PORT/json/version" -o "$TMPDIR_REAL/version.json"; then break; fi
  sleep 0.5
done
curl -sf -m 2 "http://127.0.0.1:$PORT/json/version" -o "$TMPDIR_REAL/version.json"
grep -q '"webSocketDebuggerUrl"' "$TMPDIR_REAL/version.json" || { echo "no CDP websocket in /json/version" >&2; exit 1; }
grep -qi '"Browser"' "$TMPDIR_REAL/version.json" || { echo "/json/version has no Browser" >&2; exit 1; }
echo "CDP: $(head -c 200 "$TMPDIR_REAL/version.json")"

# Page JavaScript really runs (the DOM after script execution, not the source).
"$CHROME" --headless=new --disable-gpu --user-data-dir="$PROFILE-2" --dump-dom "$URL" >"$TMPDIR_REAL/dom.html" 2>/dev/null || true
grep -q 'ark-js-ok' "$TMPDIR_REAL/dom.html" || { echo "inline script did not run" >&2; exit 1; }

# Rendering works (non-trivial PNG).
"$CHROME" --headless=new --disable-gpu --user-data-dir="$PROFILE-3" --window-size=800,600 --screenshot="$TMPDIR_REAL/shot.png" "$URL" >/dev/null 2>&1 || true
SZ=$(stat -c %s "$TMPDIR_REAL/shot.png" 2>/dev/null || echo 0)
[ "$SZ" -gt 2000 ] || { echo "screenshot too small ($SZ bytes)" >&2; exit 1; }
echo "dom: $(grep -o 'ark-js-ok' "$TMPDIR_REAL/dom.html" | head -1)   screenshot: $SZ bytes"
echo "PASS"
