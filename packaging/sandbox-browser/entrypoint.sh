#!/usr/bin/env bash
# ark sandbox browser entrypoint (OpenClaw `scripts/sandbox-browser-entrypoint.sh`, MIT).
#
# Runs a headed (or headless) Chromium plus:
#   * Xvfb            virtual display :1, 1280x800x24        (headed only)
#   * Chromium        --remote-debugging-port=9223 on loopback
#   * CDP relay       0.0.0.0:9222, requires `Authorization: Basic ark:<token>`,
#                     proxies to 127.0.0.1:9223 (HTTP + WebSocket upgrade alike)
#   * x11vnc          -localhost -rfbport 5900                (headed + noVNC only)
#   * websockify      --web=/usr/share/novnc 6080 -> 127.0.0.1:5900 (noVNC only)
#
# ark starts this container with ARK_BROWSER_CDP_AUTH_TOKEN always set; the relay is
# the only way into the browser's CDP endpoint, and it fails closed without a token.
set -Eeuo pipefail

export DBUS_SESSION_BUS_ADDRESS=/dev/null

CDP_PORT="${ARK_BROWSER_CDP_PORT:-9222}"
CHROME_CDP_PORT="${ARK_BROWSER_CHROME_CDP_PORT:-9223}"
VNC_PORT="${ARK_BROWSER_VNC_PORT:-5900}"
NOVNC_PORT="${ARK_BROWSER_NOVNC_PORT:-6080}"
AUTO_START_TIMEOUT_MS="${ARK_BROWSER_AUTO_START_TIMEOUT_MS:-12000}"
CDP_AUTH_TOKEN="${ARK_BROWSER_CDP_AUTH_TOKEN:-}"
CDP_SOURCE_RANGE="${ARK_BROWSER_CDP_SOURCE_RANGE:-}"
ENABLE_NOVNC="${ARK_BROWSER_ENABLE_NOVNC:-1}"
HEADLESS="${ARK_BROWSER_HEADLESS:-0}"
ALLOW_NO_SANDBOX="${ARK_BROWSER_NO_SANDBOX:-0}"
NOVNC_PASSWORD="${ARK_BROWSER_NOVNC_PASSWORD:-}"
DISABLE_GRAPHICS_FLAGS="${ARK_BROWSER_DISABLE_GRAPHICS_FLAGS:-1}"
DISABLE_EXTENSIONS="${ARK_BROWSER_DISABLE_EXTENSIONS:-1}"
RENDERER_PROCESS_LIMIT="${ARK_BROWSER_RENDERER_PROCESS_LIMIT:-2}"
CHROMIUM_BIN="${ARK_BROWSER_CHROMIUM:-chromium}"
DISPLAY_NUM="${ARK_BROWSER_DISPLAY:-:1}"

export HOME="${HOME:-/home/ark}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${HOME}/.cache}"
export DISPLAY="${DISPLAY_NUM}"

PROFILE_DIR="${ARK_BROWSER_PROFILE_DIR:-/tmp/ark-browser-profile}"
LOG_DIR="/tmp/ark-browser"
LOG_FILE="${LOG_DIR}/sandbox.log"

XVFB_PID=""
CHROME_PID=""
CDP_RELAY_PID=""
X11VNC_PID=""
WEBSOCKIFY_PID=""

log() { printf '[sandbox] %s\n' "$*" >&2; }

validate_uint() {
  local name="$1"
  local value="$2"
  local min="${3:-0}"
  local max="${4:-4294967295}"

  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    log "ERROR: ${name} must be an integer, got: ${value}"
    exit 1
  fi
  if (( value < min || value > max )); then
    log "ERROR: ${name} out of range (${min}..${max}), got: ${value}"
    exit 1
  fi
}

validate_uint "ARK_BROWSER_CDP_PORT" "${CDP_PORT}" 1 65535
validate_uint "ARK_BROWSER_CHROME_CDP_PORT" "${CHROME_CDP_PORT}" 1 65535
validate_uint "ARK_BROWSER_VNC_PORT" "${VNC_PORT}" 1 65535
validate_uint "ARK_BROWSER_NOVNC_PORT" "${NOVNC_PORT}" 1 65535
validate_uint "ARK_BROWSER_AUTO_START_TIMEOUT_MS" "${AUTO_START_TIMEOUT_MS}" 1 2147483647
if [[ -n "${RENDERER_PROCESS_LIMIT}" ]]; then
  validate_uint "ARK_BROWSER_RENDERER_PROCESS_LIMIT" "${RENDERER_PROCESS_LIMIT}" 0 2147483647
fi

if [[ "${CDP_PORT}" == "${CHROME_CDP_PORT}" ]]; then
  log "ERROR: ARK_BROWSER_CDP_PORT and ARK_BROWSER_CHROME_CDP_PORT must differ; ${CDP_PORT} is reserved for the authenticated CDP relay"
  exit 1
fi

# Fail closed: with no token the relay cannot authenticate anyone, and Chromium's raw
# CDP port is loopback-only, so there would be nothing to connect to. Refuse to run.
if [[ -z "${CDP_AUTH_TOKEN}" ]]; then
  log "WARNING: ARK_BROWSER_CDP_AUTH_TOKEN is unset; an unauthenticated CDP relay would expose the browser."
  log "ERROR: ARK_BROWSER_CDP_AUTH_TOKEN is required (the CDP relay refuses to start without a token)."
  exit 1
fi

cleanup() {
  local code="${1:-1}"
  trap - EXIT INT TERM

  local pids=()
  local pid
  for pid in "${WEBSOCKIFY_PID}" "${X11VNC_PID}" "${CDP_RELAY_PID}" "${CHROME_PID}" "${XVFB_PID}"; do
    if [[ -n "${pid:-}" ]]; then
      pids+=("${pid}")
    fi
  done

  if (( ${#pids[@]} > 0 )); then
    kill -TERM "${pids[@]}" 2>/dev/null || true
    local attempt alive
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      alive=0
      for pid in "${pids[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
          alive=1
          break
        fi
      done
      if (( alive == 0 )); then
        break
      fi
      sleep 0.2
    done
    kill -KILL "${pids[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
  fi

  exit "${code}"
}

trap 'cleanup "$?"' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

tail_log() {
  if [[ -s "${LOG_FILE}" ]]; then
    log "--- last 40 lines of ${LOG_FILE} ---"
    tail -n 40 "${LOG_FILE}" >&2 || true
    log "--- end of ${LOG_FILE} ---"
  fi
}

fail() {
  log "ERROR: $*"
  tail_log
  exit 1
}

mkdir -p "${LOG_DIR}" "${HOME}" "${XDG_CONFIG_HOME}" "${XDG_CACHE_HOME}" "${HOME}/.vnc" "${PROFILE_DIR}"
: > "${LOG_FILE}" 2>/dev/null || true

if [[ "${HEADLESS}" == "1" ]]; then
  log "Headless mode: no Xvfb, no x11vnc, no noVNC"
else
  Xvfb "${DISPLAY}" -screen 0 1280x800x24 -ac -nolisten tcp >>"${LOG_FILE}" 2>&1 &
  XVFB_PID=$!
  log "Xvfb started (PID: ${XVFB_PID}) on ${DISPLAY}"

  display_socket="/tmp/.X11-unix/X${DISPLAY#:}"
  attempts=0
  while (( attempts < 50 )); do
    if [[ -S "${display_socket}" ]]; then
      break
    fi
    if ! kill -0 "${XVFB_PID}" 2>/dev/null; then
      fail "Xvfb exited before creating ${display_socket}"
    fi
    sleep 0.1
    attempts=$(( attempts + 1 ))
  done
  if (( attempts >= 50 )); then
    fail "Xvfb did not create ${display_socket} within 5s"
  fi
fi

CHROME_ARGS=(
  "--remote-debugging-address=127.0.0.1"
  "--remote-debugging-port=${CHROME_CDP_PORT}"
  "--user-data-dir=${PROFILE_DIR}"
  "--no-first-run"
  "--no-default-browser-check"
  "--disable-dev-shm-usage"
  "--disable-background-networking"
  "--disable-breakpad"
  "--disable-crash-reporter"
  "--no-zygote"
  "--metrics-recording-only"
  "--password-store=basic"
  "--use-mock-keychain"
)

if [[ "${HEADLESS}" == "1" ]]; then
  CHROME_ARGS+=("--headless=new")
fi

# Sandboxing stays on unless ark explicitly asks for --no-sandbox.
if [[ "${ALLOW_NO_SANDBOX}" == "1" ]]; then
  CHROME_ARGS+=("--no-sandbox" "--disable-setuid-sandbox")
fi

DISABLE_GRAPHICS_FLAGS_LOWER="${DISABLE_GRAPHICS_FLAGS,,}"
if [[ "${DISABLE_GRAPHICS_FLAGS_LOWER}" =~ ^(1|true|yes|on)$ ]]; then
  CHROME_ARGS+=(
    "--disable-3d-apis"
    "--disable-gpu"
    "--disable-software-rasterizer"
  )
fi

DISABLE_EXTENSIONS_LOWER="${DISABLE_EXTENSIONS,,}"
if [[ "${DISABLE_EXTENSIONS_LOWER}" =~ ^(1|true|yes|on)$ ]]; then
  CHROME_ARGS+=("--disable-extensions")
fi

if [[ "${RENDERER_PROCESS_LIMIT}" =~ ^[0-9]+$ && "${RENDERER_PROCESS_LIMIT}" -gt 0 ]]; then
  CHROME_ARGS+=("--renderer-process-limit=${RENDERER_PROCESS_LIMIT}")
fi

log "Starting Chromium (upstream CDP 127.0.0.1:${CHROME_CDP_PORT}, profile ${PROFILE_DIR})"
"${CHROMIUM_BIN}" "${CHROME_ARGS[@]}" about:blank >>"${LOG_FILE}" 2>&1 &
CHROME_PID=$!
log "Chromium started (PID: ${CHROME_PID})"

start_ms=$(date +%s%3N)
deadline_ms=$(( start_ms + AUTO_START_TIMEOUT_MS ))
cdp_ready=0
log "Waiting up to ${AUTO_START_TIMEOUT_MS}ms for CDP on 127.0.0.1:${CHROME_CDP_PORT}"

while (( $(date +%s%3N) < deadline_ms )); do
  if ! kill -0 "${CHROME_PID}" 2>/dev/null; then
    fail "Chromium exited before CDP became ready"
  fi
  if curl -fsS --max-time 0.5 "http://127.0.0.1:${CHROME_CDP_PORT}/json/version" >/dev/null 2>&1; then
    cdp_ready=1
    break
  fi
  sleep 0.2
done
if (( cdp_ready == 0 )); then
  fail "CDP failed to start on 127.0.0.1:${CHROME_CDP_PORT} within ${AUTO_START_TIMEOUT_MS}ms"
fi
log "CDP ready. Starting the authenticated relay on 0.0.0.0:${CDP_PORT}"

ARK_BROWSER_CDP_PORT="${CDP_PORT}" \
ARK_BROWSER_CHROME_CDP_PORT="${CHROME_CDP_PORT}" \
ARK_BROWSER_CDP_AUTH_TOKEN="${CDP_AUTH_TOKEN}" \
ARK_BROWSER_CDP_SOURCE_RANGE="${CDP_SOURCE_RANGE}" \
python3 - >>"${LOG_FILE}" 2>&1 <<'PY' &
"""ark CDP relay: Basic-auth gate in front of Chromium's loopback DevTools port.

Every accepted connection is authenticated from its HTTP request headers and then
relayed byte-for-byte to Chromium, which means `GET /json/version`, `PUT /json/new`
and the WebSocket (`Upgrade: websocket`) session of the DevTools protocol all work
over the same socket. Tokens are compared in constant time.
"""
import base64
import hmac
import ipaddress
import os
import select
import socket
import socketserver
import sys
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ["ARK_BROWSER_CDP_PORT"])
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = int(os.environ["ARK_BROWSER_CHROME_CDP_PORT"])
AUTH_USER = os.environ.get("ARK_BROWSER_CDP_AUTH_USER", "ark")
AUTH_TOKEN = os.environ.get("ARK_BROWSER_CDP_AUTH_TOKEN", "")
SOURCE_RANGE = os.environ.get("ARK_BROWSER_CDP_SOURCE_RANGE", "").strip()
MAX_HEADER_BYTES = 65536
HEADER_READ_TIMEOUT_SECONDS = 5.0

if not AUTH_TOKEN:
    print("[sandbox] ERROR: CDP relay needs ARK_BROWSER_CDP_AUTH_TOKEN", file=sys.stderr, flush=True)
    raise SystemExit(1)

try:
    SOURCE_NETWORK = ipaddress.ip_network(SOURCE_RANGE, strict=False) if SOURCE_RANGE else None
except ValueError:
    print(f"[sandbox] ERROR: invalid ARK_BROWSER_CDP_SOURCE_RANGE: {SOURCE_RANGE}", file=sys.stderr, flush=True)
    raise SystemExit(1)

EXPECTED_BASIC = "Basic " + base64.b64encode(f"{AUTH_USER}:{AUTH_TOKEN}".encode()).decode()
EXPECTED_BEARER = "Bearer " + AUTH_TOKEN


def source_allowed(host):
    if SOURCE_NETWORK is None:
        return True
    try:
        return ipaddress.ip_address(host) in SOURCE_NETWORK
    except ValueError:
        return False


def has_auth(header_bytes):
    try:
        text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError:
        return False
    for line in text.split("\r\n")[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "authorization":
            auth = value.strip()
            return hmac.compare_digest(auth, EXPECTED_BASIC) or hmac.compare_digest(auth, EXPECTED_BEARER)
    return False


def read_headers(conn, deadline):
    data = b""
    while b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return b""
        conn.settimeout(remaining)
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            return b""
        if not chunk:
            return b""
        data += chunk
        if len(data) > MAX_HEADER_BYTES:
            return b""
    return data


def relay(left, right):
    sockets = [left, right]
    try:
        while sockets:
            readable, _, _ = select.select(sockets, [], [])
            for src in readable:
                dst = right if src is left else left
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    finally:
        for sock in (left, right):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        client_host = self.client_address[0]
        if not source_allowed(client_host):
            print(f"[sandbox] CDP relay denied source {client_host}", file=sys.stderr, flush=True)
            return
        client = self.request
        header_bytes = read_headers(client, time.monotonic() + HEADER_READ_TIMEOUT_SECONDS)
        if not header_bytes:
            return
        if not has_auth(header_bytes):
            client.sendall(
                b"HTTP/1.1 401 Unauthorized\r\n"
                b'WWW-Authenticate: Basic realm="ark CDP"\r\n'
                b"Connection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            return
        upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=5)
        upstream.settimeout(None)
        client.settimeout(None)
        upstream.sendall(header_bytes)
        relay(client, upstream)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


def main():
    with Server((LISTEN_HOST, LISTEN_PORT), Handler) as server:
        print(
            f"[sandbox] CDP relay listening on {LISTEN_HOST}:{LISTEN_PORT} "
            f"(Basic {AUTH_USER}:<token> required) -> {UPSTREAM_HOST}:{UPSTREAM_PORT}",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
PY
CDP_RELAY_PID=$!
log "CDP relay started (PID: ${CDP_RELAY_PID})"

relay_deadline=$(( $(date +%s%3N) + AUTO_START_TIMEOUT_MS ))
relay_ready=0
while (( $(date +%s%3N) < relay_deadline )); do
  if ! kill -0 "${CDP_RELAY_PID}" 2>/dev/null; then
    fail "CDP relay exited during startup"
  fi
  if curl -fsS --max-time 0.5 -u "ark:${CDP_AUTH_TOKEN}" "http://127.0.0.1:${CDP_PORT}/json/version" >/dev/null 2>&1; then
    relay_ready=1
    break
  fi
  sleep 0.2
done
if (( relay_ready == 0 )); then
  fail "authenticated CDP relay did not answer on 127.0.0.1:${CDP_PORT} within ${AUTO_START_TIMEOUT_MS}ms"
fi

# Fail closed, checked at runtime: no credentials must mean 401, never a proxied request.
unauth_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "http://127.0.0.1:${CDP_PORT}/json/version" || true)
if [[ "${unauth_code}" != "401" ]]; then
  fail "CDP relay answered an unauthenticated request with HTTP ${unauth_code:-<none>} instead of 401"
fi
log "CDP relay verified: 401 without credentials, 200 with the token"

if [[ "${ENABLE_NOVNC}" == "1" && "${HEADLESS}" != "1" ]]; then
  if [[ -z "${NOVNC_PASSWORD}" ]]; then
    NOVNC_PASSWORD="$(< /proc/sys/kernel/random/uuid)"
    NOVNC_PASSWORD="${NOVNC_PASSWORD//-/}"
    NOVNC_PASSWORD="${NOVNC_PASSWORD:0:8}"
    log "ARK_BROWSER_NOVNC_PASSWORD unset; generated a random VNC password"
  fi

  x11vnc -storepasswd "${NOVNC_PASSWORD}" "${HOME}/.vnc/passwd" >/dev/null 2>>"${LOG_FILE}"
  chmod 600 "${HOME}/.vnc/passwd"

  x11vnc -display "${DISPLAY}" -rfbport "${VNC_PORT}" -localhost -shared -forever -rfbauth "${HOME}/.vnc/passwd" >>"${LOG_FILE}" 2>&1 &
  X11VNC_PID=$!
  log "x11vnc started (PID: ${X11VNC_PID}) on 127.0.0.1:${VNC_PORT}"

  websockify --web=/usr/share/novnc "${NOVNC_PORT}" "127.0.0.1:${VNC_PORT}" >>"${LOG_FILE}" 2>&1 &
  WEBSOCKIFY_PID=$!
  log "websockify (noVNC) started (PID: ${WEBSOCKIFY_PID}) on 0.0.0.0:${NOVNC_PORT} -> 127.0.0.1:${VNC_PORT}"
elif [[ "${ENABLE_NOVNC}" == "1" ]]; then
  log "noVNC requested but headless=1: skipping x11vnc/websockify"
fi

log "Container running. CDP: 0.0.0.0:${CDP_PORT} (Basic ark:<token>) -> 127.0.0.1:${CHROME_CDP_PORT}"
if [[ -n "${WEBSOCKIFY_PID}" ]]; then
  log "noVNC: http://<host>:${NOVNC_PORT}/vnc.html?autoconnect=1 (password protected)"
else
  log "noVNC: disabled"
fi
log "Monitoring all sub-processes..."

status=0
wait -n || status=$?
log "ERROR: a sandbox-browser sub-process exited (status ${status}); shutting down"
tail_log
exit 1
