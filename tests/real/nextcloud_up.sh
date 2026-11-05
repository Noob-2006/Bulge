#!/usr/bin/env bash
# Nextcloud + Talk (spreed) for the opt-in nextcloud-talk integration test.
#
#   ./tests/real/nextcloud_up.sh --keep   # boot, print the env line, leave it running
#   eval "$(./tests/real/nextcloud_up.sh --keep)"   # …and load it into the shell
#   cargo test -p ark-channel --test real_nextcloud_talk
#   ./tests/real/nextcloud_up.sh --down   # remove the containers this script made
#
# Without --keep it boots, verifies the whole stack (user, room, bot, send and read
# back through OCS as a second user), prints the env line and removes its containers
# again — a smoke test of the harness itself. `--keep` leaves them for the test.
#
# Only containers/network/volume named `ark-test-nc*` are ever touched. Everything
# here is a throwaway local install with throwaway credentials.
#
# Image: docker.io/library/nextcloud:29.0.7-apache (SQLite, no separate DB).
# Talk:  spreed 19.0.9 (the app-store release for NC 29), installed from the
#        release tarball rather than `occ app:install spreed`, because the app
#        store is slow/flaky on this machine and `occ app:install` has no resume.
set -euo pipefail

IMAGE=docker.io/library/nextcloud:29.0.7-apache
TALK_VER=19.0.9
NET=ark-test-nc
WEB=ark-test-nc-web
DATA=ark-test-nc-data
PORT=28090
HOOK_PORT=28091
BASE="http://127.0.0.1:$PORT"
ADMIN=arkadmin
ADMIN_PASS='ark-e2e-Admin-1'
PEER=arkpeer
PEER_PASS='ark-e2e-Peer-1'
BOTUSER=arkbot
BOTUSER_PASS='ark-e2e-Botuser-1'
BOT_NAME=Ark
ROOM_NAME=ark-e2e
TARBALL_URL="https://github.com/nextcloud-releases/spreed/releases/download/v$TALK_VER/spreed-v$TALK_VER.tar.gz"
CACHE="${TMPDIR:-/home/noob/.cache/ark-build/r6-be/nc}"
TARBALL="$CACHE/spreed-v$TALK_VER.tar.gz"

KEEP=0
DOWN=0
for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    --down) DOWN=1 ;;
    *) echo "unknown flag $a" >&2; exit 2 ;;
  esac
done

log() { echo "[nc-up] $*" >&2; }
die() { echo "[nc-up] FAILED: $*" >&2; exit 1; }

occ() { podman exec -u www-data "$WEB" php /var/www/html/occ "$@"; }

down() {
  podman rm -f "$WEB" >/dev/null 2>&1 || true
  podman volume rm -f "$DATA" >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
}

# ocs METHOD PATH [curl args…] — as the admin, JSON.
ocs() {
  local method=$1 path=$2; shift 2
  curl -sS -u "$ADMIN:$ADMIN_PASS" -H 'OCS-APIRequest: true' -H 'Accept: application/json' -X "$method" "$@" "$BASE$path"
}

# ocs_as USER PASS METHOD PATH [args…]
ocs_as() {
  local u=$1 p=$2 method=$3 path=$4; shift 4
  curl -sS -u "$u:$p" -H 'OCS-APIRequest: true' -H 'Accept: application/json' -X "$method" "$@" "$BASE$path"
}

wait_http() { # url, seconds
  local url=$1 n=${2:-180}
  for _ in $(seq 1 "$n"); do
    if curl -sf -o /dev/null "$url"; then return 0; fi
    sleep 1
  done
  return 1
}

if [ "$DOWN" -eq 1 ]; then
  down
  log "removed $WEB, $DATA, $NET"
  exit 0
fi

cleanup() {
  local rc=$?
  if [ "$KEEP" -eq 1 ]; then
    log "keeping $WEB (remove with: $0 --down)"
    return
  fi
  down
  exit $rc
}
trap cleanup EXIT

command -v podman >/dev/null || die "podman not found"
podman container exists "$WEB" && { log "removing a stale $WEB from an earlier run"; podman rm -f "$WEB" >/dev/null; }
podman volume exists "$DATA" 2>/dev/null && podman volume rm -f "$DATA" >/dev/null 2>&1 || true
podman network exists "$NET" || podman network create "$NET" >/dev/null

if [ ! -s "$TARBALL" ]; then
  mkdir -p "$CACHE"
  log "downloading Talk $TALK_VER (~42 MB)…"
  curl -sSL --retry 3 -o "$TARBALL.part" "$TARBALL_URL" && mv "$TARBALL.part" "$TARBALL" || die "cannot download $TARBALL_URL"
fi

log "starting $WEB ($IMAGE)"
podman run -d --name "$WEB" --network "$NET" -p "127.0.0.1:$PORT:80" \
  -v "$DATA:/var/www/html" \
  -e SQLITE_DATABASE=nc \
  -e NEXTCLOUD_ADMIN_USER="$ADMIN" -e NEXTCLOUD_ADMIN_PASSWORD="$ADMIN_PASS" \
  -e NEXTCLOUD_TRUSTED_DOMAINS="127.0.0.1 localhost host.containers.internal" \
  -e PHP_MEMORY_LIMIT=768M \
  "$IMAGE" >/dev/null || die "podman run"

wait_http "$BASE/status.php" 240 || { podman logs --tail 40 "$WEB" >&2; die "Nextcloud did not come up on $BASE"; }
for _ in $(seq 1 120); do
  if curl -sf "$BASE/status.php" | grep -q '"installed":true'; then break; fi
  sleep 1
done
curl -sf "$BASE/status.php" | grep -q '"installed":true' || die "Nextcloud did not finish installing"
log "Nextcloud $(curl -sS "$BASE/status.php" | sed -n 's/.*"versionstring":"\([^"]*\)".*/\1/p') up"

# The webhook `X-Nextcloud-Talk-Backend` header is overwrite.cli.url + "/", so pin it.
occ config:system:set overwrite.cli.url --value="$BASE" >/dev/null
occ config:system:set overwriteprotocol --value=http >/dev/null

log "installing Talk $TALK_VER"
podman cp "$TARBALL" "$WEB:/tmp/spreed.tar.gz" >/dev/null
podman exec "$WEB" bash -c 'rm -rf /var/www/html/apps/spreed && tar xzf /tmp/spreed.tar.gz -C /var/www/html/apps && chown -R www-data:www-data /var/www/html/apps/spreed && rm -f /tmp/spreed.tar.gz' || die "cannot unpack Talk"
occ app:enable spreed >/dev/null || die "cannot enable spreed"
occ app:enable spreed >/dev/null 2>&1 || true
log "Talk $(occ app:list 2>/dev/null | grep -o 'spreed: [0-9.]*' || echo enabled)"

# Second user (the "human" whose messages must reach ark) and the API user whose
# app password ark uses for room lookups / WebDAV.
for u in "$PEER" "$BOTUSER"; do
  occ user:get "$u" >/dev/null 2>&1 && occ user:delete "$u" >/dev/null 2>&1 || true
done
podman exec -u www-data -e OC_PASS="$PEER_PASS" "$WEB" php /var/www/html/occ user:add --password-from-env --display-name "Ark Peer" "$PEER" >/dev/null || die "cannot create $PEER"
podman exec -u www-data -e OC_PASS="$BOTUSER_PASS" "$WEB" php /var/www/html/occ user:add --password-from-env --display-name "Ark API user" "$BOTUSER" >/dev/null || die "cannot create $BOTUSER"

# App password for the API user (falls back to the login password where the
# occ subcommand is missing).
APP_PASS=$BOTUSER_PASS
if occ list user 2>/dev/null | grep -q 'user:add-app-password'; then
  # `user:add-app-password` re-reads the account password from NC_PASS (not OC_PASS)
  # and prints the token after an "app password:" line.
  APP_PASS=$(podman exec -u www-data -e NC_PASS="$BOTUSER_PASS" "$WEB" php /var/www/html/occ user:add-app-password --password-from-env "$BOTUSER" 2>/dev/null | tr -d '\r' | tail -1 | tr -d ' ') || APP_PASS=$BOTUSER_PASS
  if [ ${#APP_PASS} -lt 20 ]; then APP_PASS=$BOTUSER_PASS; else log "app password for $BOTUSER issued"; fi
fi

# Room + the peer (the human) and the API user as participants: the API user's app
# password only authenticates ark's room lookups/WebDAV, but the test also posts as
# it, and posting to a conversation requires being in it.
ROOM=$(ocs POST /ocs/v2.php/apps/spreed/api/v4/room -d "roomType=3" -d "roomName=$ROOM_NAME" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$ROOM" ] || die "cannot create a conversation: $(ocs POST /ocs/v2.php/apps/spreed/api/v4/room -d 'roomType=3' -d "roomName=$ROOM_NAME")"
for u in "$PEER" "$BOTUSER"; do
  ocs POST "/ocs/v2.php/apps/spreed/api/v4/room/$ROOM/participants" -d "newParticipant=$u" | grep -q '"statuscode":200' || die "cannot add $u to $ROOM"
done
log "conversation $ROOM with $ADMIN + $PEER + $BOTUSER"

# The bot: webhook in, response (message/reaction) out. The URL must be reachable
# from inside the container, so the test listens on 0.0.0.0:$HOOK_PORT and the bot
# points at the host as seen from the container.
SECRET=$( (head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n') )
[ ${#SECRET} -ge 40 ] || die "bot secret too short"
HOOK="http://host.containers.internal:$HOOK_PORT/nextcloud-talk-webhook"
occ talk:bot:install --feature webhook --feature response --feature reaction "$BOT_NAME" "$SECRET" "$HOOK" "ark e2e bot" >/dev/null || die "talk:bot:install"
BOT_LIST=$(occ talk:bot:list)
BOT_ID=$(printf '%s\n' "$BOT_LIST" | grep -F "$BOT_NAME" | grep -o '[0-9]\+' | head -1)
[ -n "$BOT_ID" ] || die "cannot find the bot id in: $BOT_LIST"
# Enabled per conversation (a bot must be enabled in the room to post or receive).
ocs POST "/ocs/v2.php/apps/spreed/api/v1/bot/$ROOM/$BOT_ID" >/dev/null || die "cannot enable bot $BOT_ID in $ROOM"
log "bot $BOT_ID ($BOT_NAME) enabled in $ROOM -> $HOOK"

# Self-check: the peer posts through the plain chat API and reads it back.
SELF=$(ocs_as "$PEER" "$PEER_PASS" POST "/ocs/v2.php/apps/spreed/api/v1/chat/$ROOM" -d "message=nc-up self check")
printf '%s' "$SELF" | grep -q '"status":"ok"' || die "peer cannot post: $SELF"
MSG=$(ocs_as "$PEER" "$PEER_PASS" GET "/ocs/v2.php/apps/spreed/api/v1/chat/$ROOM?lookIntoFuture=0&limit=50&noStatusUpdate=1&setReadMarker=0&markNotificationsAsRead=0")
printf '%s' "$MSG" | grep -q 'nc-up self check' || die "peer cannot read back: $MSG"
# WebDAV write path (what ark uses for attachments): a cold instance can 500 on the
# first write, so prove it here before the tests depend on it.
curl -sS -o /dev/null -w '%{http_code}' -u "$ADMIN:$ADMIN_PASS" -X MKCOL "$BASE/remote.php/dav/files/$ADMIN/Ark-nc-up" | grep -qE '201|405' || die "WebDAV MKCOL failed"
DAVCODE=$(curl -sS -o /dev/null -w '%{http_code}' -u "$ADMIN:$ADMIN_PASS" -X PUT -H 'content-type: text/plain' --data-binary 'nc-up' "$BASE/remote.php/dav/files/$ADMIN/Ark-nc-up/probe.txt")
if [ "$DAVCODE" != 201 ] && [ "$DAVCODE" != 204 ]; then
  sleep 1
  DAVCODE=$(curl -sS -o /dev/null -w '%{http_code}' -u "$ADMIN:$ADMIN_PASS" -X PUT -H 'content-type: text/plain' --data-binary 'nc-up' "$BASE/remote.php/dav/files/$ADMIN/Ark-nc-up/probe.txt")
fi
[ "$DAVCODE" = 201 ] || [ "$DAVCODE" = 204 ] || die "WebDAV PUT failed ($DAVCODE)"

# Talk's bot endpoints are brute-force protected per client IP and the delay grows to
# 25 s after a few rejected signatures (the test's wrong-secret case counts). Clear
# the counter for the container network's gateway, which is where test requests come
# from, so a run starts without a penalty.
GW=$(podman network inspect "$NET" --format '{{(index .Subnets 0).Gateway}}' 2>/dev/null || true)
if [ -n "$GW" ]; then occ security:bruteforce:reset "$GW" >/dev/null 2>&1 || true; fi

ENV_LINE="export ARK_REAL_NEXTCLOUD_URL=$BASE ARK_REAL_NEXTCLOUD_USER=$BOTUSER ARK_REAL_NEXTCLOUD_PASSWORD=$APP_PASS ARK_REAL_NEXTCLOUD_PEER=$PEER ARK_REAL_NEXTCLOUD_PEER_PASSWORD=$PEER_PASS ARK_REAL_NEXTCLOUD_ADMIN=$ADMIN ARK_REAL_NEXTCLOUD_ADMIN_PASSWORD=$ADMIN_PASS ARK_REAL_NEXTCLOUD_ROOM=$ROOM ARK_REAL_NEXTCLOUD_BOT_ID=$BOT_ID ARK_REAL_NEXTCLOUD_BOT_NAME=$BOT_NAME ARK_REAL_NEXTCLOUD_BOT_SECRET=$SECRET ARK_REAL_NEXTCLOUD_WEBHOOK_PORT=$HOOK_PORT"
echo "$ENV_LINE"
log "stack ready"
