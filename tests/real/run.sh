#!/usr/bin/env bash
# Real-service integration tests for ark's channels.
#
# Starts the services this machine can self-host, runs the opt-in tests in
# `crates/ark-channel/tests/real_*.rs`, then removes every container it started.
# Nothing here touches $HOME or the real $ARK_HOME: the tests get addresses in
# env vars and scratch dirs under $TMPDIR.
#
#   ./tests/real/run.sh              # everything
#   ./tests/real/run.sh --no-matrix  # skip Synapse (pulls ~340 MB, ~25 s boot)
#   ./tests/real/run.sh --keep       # leave the services running
#
# Heavy extras (each pulls an image or ~150 MB of wheels; `--no-<name>` skips one):
#   --no-mattermost   Mattermost + Postgres (E1, ~730 MB image)
#   --no-nextcloud    Nextcloud + Talk/spreed (E1, ~1.3 GB image)
#   --no-tts          local Piper TTS in a venv under $TMPDIR (E5)
#   --no-sandbox      the sandbox-browser image (B7, built from packaging/)
#
# Requires: podman, cargo, curl, node/npm (only for the WhatsApp bridge),
# a whisper.cpp build for the STT test (see docs/protocols/README.md).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR_REAL="${TMPDIR:-/tmp}/ark-real-$$"
mkdir -p "$TMPDIR_REAL"
export TMPDIR="$TMPDIR_REAL"
export CARGO_INCREMENTAL=0

PREFIX=ark-real
PORTS=(25860 25825 25843 25880 28008 26667 25999)
WITH_MATRIX=1
WITH_WHATSAPP=1
WITH_MATTERMOST=1
WITH_NEXTCLOUD=1
WITH_TTS=1
WITH_SANDBOX=1
KEEP=0
for a in "$@"; do
  case "$a" in
    --no-matrix) WITH_MATRIX=0 ;;
    --no-whatsapp) WITH_WHATSAPP=0 ;;
    --no-mattermost) WITH_MATTERMOST=0 ;;
    --no-nextcloud) WITH_NEXTCLOUD=0 ;;
    --no-tts) WITH_TTS=0 ;;
    --no-sandbox) WITH_SANDBOX=0 ;;
    --keep) KEEP=1 ;;
    *) echo "unknown flag $a" >&2; exit 2 ;;
  esac
done

started_containers=()
started_pids=()
# Stacks owned by another agent (mattermost_up.sh / nextcloud_up.sh) that this run
# started and must therefore take down again.
started_stacks=()

cleanup() {
  local rc=$?
  if [ "$KEEP" -eq 1 ]; then
    echo "keeping services: ${started_containers[*]:-none} ${started_pids[*]:-} ${started_stacks[*]:-}"
    return
  fi
  for c in "${started_containers[@]:-}"; do
    [ -n "$c" ] && podman rm -f "$c" >/dev/null 2>&1 || true
  done
  for p in "${started_pids[@]:-}"; do
    # Only processes this script started, by pid.
    [ -n "$p" ] && kill "$p" >/dev/null 2>&1 || true
  done
  for s in "${started_stacks[@]:-}"; do
    # Each helper removes only the ark-test-<stack>* containers it created.
    [ -n "$s" ] && "$ROOT/tests/real/${s}_up.sh" --down >/dev/null 2>&1 || true
  done
  rm -rf "$TMPDIR_REAL"
  exit $rc
}
trap cleanup EXIT INT TERM

wait_http() { # url, seconds
  local url=$1 n=${2:-60}
  for _ in $(seq 1 "$n"); do
    curl -sf -m 2 -o /dev/null "$url" && return 0
    sleep 1
  done
  echo "timed out waiting for $url" >&2
  return 1
}

# --- ntfy ---------------------------------------------------------------
podman rm -f "$PREFIX-ntfy" >/dev/null 2>&1 || true
podman run -d --name "$PREFIX-ntfy" -p 25860:80 docker.io/binwiederhier/ntfy:latest serve --listen-http :80 >/dev/null
started_containers+=("$PREFIX-ntfy")
wait_http http://127.0.0.1:25860/v1/health 60
export ARK_REAL_NTFY_URL=http://127.0.0.1:25860

# --- SMTP + IMAP (GreenMail) --------------------------------------------
podman rm -f "$PREFIX-mail" >/dev/null 2>&1 || true
podman run -d --name "$PREFIX-mail" -p 25825:3025 -p 25843:3143 -p 25880:8080 \
  -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=ark:secret@localhost,alice:secret@localhost' \
  docker.io/greenmail/standalone >/dev/null
started_containers+=("$PREFIX-mail")
wait_http http://127.0.0.1:25880/api/user/ark@localhost/messages 120
export ARK_REAL_IMAP=127.0.0.1:25843 ARK_REAL_SMTP=127.0.0.1:25825 ARK_REAL_MAIL_API=http://127.0.0.1:25880
export ARK_REAL_MAIL_USER=ark ARK_REAL_MAIL_PASS=secret ARK_REAL_MAIL_ADDR=ark@localhost

# --- IRC (ngircd, from the distro package, no root) ---------------------
if command -v ngircd >/dev/null 2>&1; then
  NGIRCD=$(command -v ngircd)
else
  DEB="$TMPDIR_REAL/deb"
  mkdir -p "$DEB"
  ( cd "$DEB" && apt-get download ngircd libident0 >/dev/null 2>&1 ) || true
  for d in "$DEB"/*.deb; do [ -e "$d" ] && dpkg-deb -x "$d" "$DEB/root"; done
  NGIRCD="$DEB/root/usr/sbin/ngircd"
  export LD_LIBRARY_PATH="$DEB/root/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
fi
if [ -x "$NGIRCD" ]; then
  cat > "$TMPDIR_REAL/ngircd.conf" <<EOF
[Global]
    Name = ark-real.local
    Info = ark real-service test ircd
    Ports = 26667
    Listen = 127.0.0.1
    PidFile = $TMPDIR_REAL/ngircd.pid
    MotdPhrase = ark real irc test
    Ident = no
    DNS = no
[Options]
    PAM = no
    ConnectIPv4 = yes
    ConnectIPv6 = no
EOF
  "$NGIRCD" -f "$TMPDIR_REAL/ngircd.conf" -n > "$TMPDIR_REAL/ngircd.log" 2>&1 &
  started_pids+=("$!")
  for _ in $(seq 1 20); do (exec 3<>/dev/tcp/127.0.0.1/26667) 2>/dev/null && break; sleep 0.5; done
  export ARK_REAL_IRC_ADDR=127.0.0.1:26667
else
  echo "ngircd not available: skipping the IRC tests" >&2
fi

# --- Matrix (Synapse) ---------------------------------------------------
if [ "$WITH_MATRIX" -eq 1 ]; then
  podman rm -f "$PREFIX-synapse" >/dev/null 2>&1 || true
  SYNDATA="$TMPDIR_REAL/synapse"
  mkdir -p "$SYNDATA"; chmod 777 "$SYNDATA"
  podman run --rm --user 991:991 -v "$SYNDATA:/data" -e SYNAPSE_SERVER_NAME=localhost -e SYNAPSE_REPORT_STATS=no \
    docker.io/matrixdotorg/synapse:latest generate >/dev/null 2>&1
  python3 - "$SYNDATA/homeserver.yaml" <<'PY'
import os, sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('server_name: "localhost"', 'server_name: "localhost"\npublic_baseurl: "http://127.0.0.1:28008/"', 1)
if 'rc_login' not in s:
    s += ('\nenable_registration: true\nenable_registration_without_verification: true\n'
          'rc_login:\n  address: {per_second: 100, burst_count: 1000}\n'
          '  account: {per_second: 100, burst_count: 1000}\n'
          '  failed_attempts: {per_second: 100, burst_count: 1000}\n'
          'rc_message: {per_second: 100, burst_count: 1000}\n')
os.remove(p)
open(p, 'w').write(s)
os.chmod(p, 0o666)
PY
  podman run -d --name "$PREFIX-synapse" -p 28008:8008 -v "$SYNDATA:/data" --user 991:991 docker.io/matrixdotorg/synapse:latest >/dev/null
  started_containers+=("$PREFIX-synapse")
  wait_http http://127.0.0.1:28008/_matrix/client/versions 180
  podman exec "$PREFIX-synapse" register_new_matrix_user -u ark -p arkpass123 -a -c /data/homeserver.yaml http://localhost:8008 >/dev/null 2>&1 || true
  podman exec "$PREFIX-synapse" register_new_matrix_user -u alice -p alicepass123 --no-admin -c /data/homeserver.yaml http://localhost:8008 >/dev/null 2>&1 || true
  export ARK_REAL_MATRIX_HS=http://127.0.0.1:28008 ARK_REAL_MATRIX_USER=@ark:localhost ARK_REAL_MATRIX_PASS=arkpass123
  export ARK_REAL_MATRIX_PEER=@alice:localhost ARK_REAL_MATRIX_PEER_PASS=alicepass123
fi

# --- WhatsApp bridge (real Baileys process, unpaired) -------------------
if [ "$WITH_WHATSAPP" -eq 1 ] && command -v node >/dev/null 2>&1 && [ -d "$ROOT/bridges/whatsapp/node_modules" ]; then
  # Invoke node directly (not through a subshell) so `$!` is the process to stop.
  node "$ROOT/bridges/whatsapp/bridge.js" --port 25999 --session "$TMPDIR_REAL/wa-session" --mode bot > "$TMPDIR_REAL/wa.log" 2>&1 &
  started_pids+=("$!")
  for _ in $(seq 1 60); do curl -sf -m 2 http://127.0.0.1:25999/health >/dev/null 2>&1 && break; sleep 1; done
  export ARK_REAL_WA_BRIDGE=http://127.0.0.1:25999
else
  echo "whatsapp bridge not run (node or bridges/whatsapp/node_modules missing)" >&2
fi

# --- whisper.cpp STT (bring your own build) -----------------------------
if [ -n "${ARK_REAL_WHISPER_CPP:-}" ]; then
  mkdir -p "$TMPDIR_REAL/whisper-models"
  export ARK_REAL_WHISPER_MODELS="$TMPDIR_REAL/whisper-models"
fi

# --- Mattermost + Postgres (real API v4 + websocket) ---------------------
if [ "$WITH_MATTERMOST" -eq 1 ]; then
  if "$ROOT/tests/real/mattermost_up.sh" --keep > "$TMPDIR_REAL/mattermost.env" 2> "$TMPDIR_REAL/mattermost.log"; then
    # shellcheck disable=SC1091
    . "$TMPDIR_REAL/mattermost.env"
    started_stacks+=("mattermost")
  else
    echo "Mattermost stack did not come up (see $TMPDIR_REAL/mattermost.log); its tests will skip" >&2
    tail -n 5 "$TMPDIR_REAL/mattermost.log" >&2 || true
  fi
fi

# --- Nextcloud Talk (real OCS chat API + bot webhooks) -------------------
if [ "$WITH_NEXTCLOUD" -eq 1 ]; then
  if "$ROOT/tests/real/nextcloud_up.sh" --keep > "$TMPDIR_REAL/nextcloud.env" 2> "$TMPDIR_REAL/nextcloud.log"; then
    # shellcheck disable=SC1091
    . "$TMPDIR_REAL/nextcloud.env"
    started_stacks+=("nextcloud")
  else
    echo "Nextcloud stack did not come up (see $TMPDIR_REAL/nextcloud.log); its tests will skip" >&2
    tail -n 5 "$TMPDIR_REAL/nextcloud.log" >&2 || true
  fi
fi

# --- Local TTS (Piper) ---------------------------------------------------
if [ "$WITH_TTS" -eq 1 ]; then
  if "$ROOT/tests/real/tts_up.sh" > "$TMPDIR_REAL/tts.env" 2> "$TMPDIR_REAL/tts.log"; then
    # shellcheck disable=SC1091
    . "$TMPDIR_REAL/tts.env"
  else
    echo "local Piper install failed (see $TMPDIR_REAL/tts.log); the TTS test will skip" >&2
  fi
fi

# --- Sandbox browser (B7): build the image, let the test drive it --------
if [ "$WITH_SANDBOX" -eq 1 ]; then
  if "$ROOT/tests/real/sandbox_browser_up.sh" > "$TMPDIR_REAL/sandbox.env" 2> "$TMPDIR_REAL/sandbox.log"; then
    # shellcheck disable=SC1091
    . "$TMPDIR_REAL/sandbox.env"
  else
    echo "sandbox-browser image not available (see $TMPDIR_REAL/sandbox.log); its test will skip" >&2
    tail -n 5 "$TMPDIR_REAL/sandbox.log" >&2 || true
  fi
fi

cd "$ROOT"
status=0
for t in real_ntfy real_email real_irc real_matrix real_whatsapp real_media real_mattermost real_nextcloud_talk vectors; do
  echo "=== cargo test -p ark-channel --test $t"
  # real_irc's cases share one ircd, one channel (#ark) and assert "nothing else arrived
  # yet", so they must not interleave; the others use separate rooms/users per test.
  if [ "$t" = real_irc ]; then
    cargo test -p ark-channel --test "$t" -- --test-threads=1 2>&1 | tail -n 6 || status=1
  else
    cargo test -p ark-channel --test "$t" 2>&1 | tail -n 6 || status=1
  fi
done
echo "=== cargo test -p ark-media --test real_tts"
cargo test -p ark-media --test real_tts 2>&1 | tail -n 6 || status=1
echo "=== cargo test -p ark-browser --test real_sandbox_browser"
cargo test -p ark-browser --test real_sandbox_browser 2>&1 | tail -n 8 || status=1
echo "=== done (status $status); services will be removed"
exit $status
