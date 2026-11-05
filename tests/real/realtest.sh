#!/usr/bin/env bash
# Real-environment suite (gen1-303/304/305/308, gen2-518, new-001): every `#[ignore]` case
# gated on ARK_REAL_TESTS=1, run in one go, with a summary at the end.
#
#   tests/real/realtest.sh                 # everything this host can run
#   tests/real/realtest.sh --only browser  # browser | backends | desktop | webui | longtask | orphans
#   tests/real/realtest.sh --rmi           # also remove the test image afterwards
#
# Needs: cargo, a Chromium-family browser (browser, webui), podman (backends, desktop, ssh),
# bwrap. docker is optional (its case reports SKIPPED without a client).
# Creates only `ark-test-realtest-*` containers, the `localhost/ark-test-realtest` image and
# files under $TMPDIR/ark-realtest-$$; all of it is removed on exit (also on Ctrl-C).
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT_DIR=$PWD
export TMPDIR="${TMPDIR:-/tmp}" ARK_OFFLINE=1 ARK_REAL_TESTS=1
WORK="$TMPDIR/ark-realtest-$$"
mkdir -p "$WORK/tmp"
# Everything the tests create under $TMPDIR (scratch homes, the ssh ControlPath dir) lands
# in $WORK and goes with it.
export TMPDIR="$WORK/tmp"
IMAGE=localhost/ark-test-realtest:latest
SSHD="ark-test-realtest-sshd-$$"
DESK="ark-test-realtest-desktop-$$"
ONLY="" RMI=0
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --rmi) RMI=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

cleanup() {
  podman rm -f -t 1 "$SSHD" "$DESK" >/dev/null 2>&1 || true
  [ "$RMI" = 1 ] && podman rmi -f "$IMAGE" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

declare -a SUMMARY
want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }
record() { SUMMARY+=("$(printf '%-9s %-6s %s' "$1" "$2" "$3")"); }

# Runs a cargo test command, records pass/fail and the test-result line.
suite() {
  local name="$1"; shift
  echo "== $name: $*"
  local log="$WORK/$name.log"
  "$@" >"$log" 2>&1
  local rc=$?
  grep -E '^test |SKIPPED|^test result|panicked' "$log"
  local res; res=$(grep -E '^test result' "$log" | tail -1)
  local skipped; skipped=$(grep -o 'SKIPPED [a-z_]*' "$log" | sed 's/SKIPPED //' | tr '\n' ' ')
  if [ "$rc" = 0 ]; then record "$name" PASS "${res#test result: } ${skipped:+(skipped: $skipped)}"; else record "$name" FAIL "${res#test result: }"; fi
}

ensure_image() {
  podman image exists "$IMAGE" && return 0
  echo "== building $IMAGE (one time, ~700 MB)"
  podman build -q -t "$IMAGE" -f tests/real/realtest/Containerfile tests/real/realtest >/dev/null
}

if want orphans; then
  suite orphans cargo test -q -p ark-core proc:: -- --test-threads=1
  suite orphans2 cargo test -q -p ark-browser --lib tests_real::launcher -- --test-threads=1
  suite orphans3 cargo test -q -p ark --test daemon_orphan
fi

if want browser; then
  suite browser cargo test -p ark-browser --lib tests_real -- --ignored --test-threads=1
fi

if want backends; then
  SSH_ENV=()
  if command -v podman >/dev/null && ensure_image; then
    ssh-keygen -q -t ed25519 -N '' -f "$WORK/key" >/dev/null
    chmod 644 "$WORK/key.pub"
    if podman run -d --name "$SSHD" -p 127.0.0.1::22 -v "$WORK/key.pub:/root/.ssh/authorized_keys:ro" "$IMAGE" \
         sh -c 'ssh-keygen -A >/dev/null && exec /usr/sbin/sshd -D -e' >/dev/null; then
      PORT=$(podman port "$SSHD" 22/tcp | head -1 | sed 's/.*://')
      for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.2; done
      SSH_ENV=(ARK_REAL_SSH_PORT="$PORT" ARK_REAL_SSH_KEY="$WORK/key" ARK_REAL_SSH_USER=root)
    fi
  fi
  suite backends env "${SSH_ENV[@]}" cargo test -p ark-tools --lib real_backend -- --ignored --test-threads=1 --nocapture
  podman rm -f -t 1 "$SSHD" >/dev/null 2>&1 || true
fi

if want desktop; then
  if command -v podman >/dev/null && ensure_image; then
    BIN=$(cargo test -p ark-app --lib --no-run --message-format=json 2>/dev/null | python3 -I -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("target", {}).get("name") == "ark_app" and m.get("profile", {}).get("test") and m.get("executable"):
        print(m["executable"])' | tail -1)
    suite desktop podman run --rm --name "$DESK" --userns=keep-id --user "$(id -u):$(id -g)" \
      -e HOME=/tmp/h -e TMPDIR=/tmp -e ARK_REAL_TESTS=1 -e ARK_REAL_DESKTOP=1 -e ARK_OFFLINE=1 \
      -v "$BIN:/t/ark-app-tests:ro" "$IMAGE" \
      sh -c 'mkdir -p /tmp/h && exec /t/ark-app-tests --ignored --exact computer::tests_real::real_bot_desktop_computer_use --test-threads=1'
  else
    record desktop SKIP "podman missing or image build failed"
  fi
fi

if want webui; then
  suite webui cargo test -p ark --test webui_browser -- --ignored --test-threads=1
fi

if want longtask; then
  suite longtask cargo test -p ark-kernel --lib longtask -- --test-threads=1
fi

echo
echo "================ realtest summary ================"
printf '%s\n' "${SUMMARY[@]}"
echo "leftover ark-test-realtest containers: $(podman ps -a --format '{{.Names}}' 2>/dev/null | grep -c "ark-test-realtest-.*-$$" || true)"
printf '%s\n' "${SUMMARY[@]}" | grep -q ' FAIL ' && exit 1
exit 0
