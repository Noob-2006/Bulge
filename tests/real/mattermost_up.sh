#!/usr/bin/env bash
# Start a real Mattermost (team edition) + Postgres for the ark Mattermost
# integration test (`crates/ark-channel/tests/real_mattermost.rs`).
#
#   eval "$(./tests/real/mattermost_up.sh --keep)"   # start, print env, leave it running
#   ./tests/real/mattermost_up.sh                    # start, print env, remove it again
#   ./tests/real/mattermost_up.sh --down             # remove a stack started with --keep
#
# `--keep` leaves the stack running for the test; without it every container
# (and the network) this script created is removed on exit, on success and on
# failure alike. Nothing else is ever touched.
#
# Only the containers/networks named `ark-test-mm*` are touched; nothing in
# `$HOME`/`$ARK_HOME` is read or written. The stack is:
#
#   ark-test-mm-db   postgres:16-alpine
#   ark-test-mm-web  mattermost/mattermost-team-edition:latest  -> 127.0.0.1:28065
#
# On success it prints the environment the test expects:
#
#   export ARK_REAL_MATTERMOST_URL=http://127.0.0.1:28065
#   export ARK_REAL_MATTERMOST_TOKEN=<bot personal access token>
#   export ARK_REAL_MATTERMOST_CHANNEL=<public channel id>
#   export ARK_REAL_MATTERMOST_TEAM=<team id>
#   export ARK_REAL_MATTERMOST_PEER_TOKEN=<human personal access token>
#   export ARK_REAL_MATTERMOST_PEER_ID=<human user id>
#   export ARK_REAL_MATTERMOST_BOT_ID=<bot user id>
#   export ARK_REAL_MATTERMOST_BOT2_TOKEN=<second bot token>
#   export ARK_REAL_MATTERMOST_BOT2_ID=<second bot user id>
set -euo pipefail

NET=ark-test-mm
DB=ark-test-mm-db
WEB=ark-test-mm-web
PORT=28065
URL="http://127.0.0.1:${PORT}"
ADMIN_EMAIL=admin@ark.test
ADMIN_USER=arkadmin
ADMIN_PASS='Ark-Admin-1!'
PEER_EMAIL=peer@ark.test
PEER_USER=arkpeer
PEER_PASS='Ark-Peer-1!'
BOT_USER=arkbot

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

MADE_NET=0
KEEP=0

down() {
  podman rm -f "$WEB" "$DB" >/dev/null 2>&1 || true
  [ "$MADE_NET" = 1 ] && podman network rm "$NET" >/dev/null 2>&1 || true
}

cleanup() {
  [ "$KEEP" = 1 ] && return 0
  down
  log "removed $WEB $DB ${NET:+$NET} (use --keep to keep the stack)"
}

case "${1:-}" in
  --down) KEEP=1; MADE_NET=1; down; log "removed $WEB $DB $NET"; exit 0 ;;
  --keep) KEEP=1 ;;
  "") ;;
  *) die "unknown flag $1" ;;
esac
trap cleanup EXIT

command -v podman >/dev/null || die "podman not found"
command -v curl >/dev/null || die "curl not found"

podman image exists docker.io/library/postgres:16-alpine || die "missing image postgres:16-alpine (podman pull docker.io/library/postgres:16-alpine)"
podman image exists docker.io/mattermost/mattermost-team-edition:latest || die "missing image mattermost/mattermost-team-edition:latest (podman pull it first)"

# Reuse only a stack this script owns; stale copies (names below) are removed first.
podman rm -f "$WEB" "$DB" >/dev/null 2>&1 || true
podman network rm "$NET" >/dev/null 2>&1 || true
podman network create "$NET" >/dev/null
MADE_NET=1

podman run -d --name "$DB" --network "$NET" --network-alias "$DB" \
  -e POSTGRES_USER=mmuser -e POSTGRES_PASSWORD=arkmmtest -e POSTGRES_DB=mattermost \
  docker.io/library/postgres:16-alpine >/dev/null
log "started $DB"

# Wait for Postgres to accept connections before Mattermost migrates.
for i in $(seq 1 60); do
  if podman exec "$DB" pg_isready -U mmuser -d mattermost >/dev/null 2>&1; then break; fi
  [ "$i" = 60 ] && die "postgres did not become ready"
  sleep 1
done
log "postgres ready"

podman run -d --name "$WEB" --network "$NET" \
  -p "127.0.0.1:${PORT}:8065" \
  -e MM_SQLSETTINGS_DRIVERNAME=postgres \
  -e "MM_SQLSETTINGS_DATASOURCE=postgres://mmuser:arkmmtest@${DB}:5432/mattermost?sslmode=disable&connect_timeout=10" \
  -e "MM_SERVICESETTINGS_SITEURL=${URL}" \
  -e MM_SERVICESETTINGS_ENABLESECURITYFIXALERT=false \
  -e MM_SERVICESETTINGS_ENABLEUSERACCESSTOKENS=true \
  -e MM_SERVICESETTINGS_ENABLEBOTACCOUNTCREATION=true \
  -e MM_TEAMSETTINGS_ENABLEOPENSERVER=true \
  -e MM_LOGSETTINGS_CONSOLELEVEL=ERROR \
  -e MM_FILESETTINGS_DIRECTORY=/mattermost/data \
  docker.io/mattermost/mattermost-team-edition:latest >/dev/null
log "started $WEB; waiting for ${URL}/api/v4/system/ping (first boot runs migrations)"

for i in $(seq 1 180); do
  if curl -fsS "${URL}/api/v4/system/ping" >/dev/null 2>&1; then break; fi
  if ! podman container exists "$WEB" || [ "$(podman inspect -f '{{.State.Running}}' "$WEB" 2>/dev/null)" != true ]; then
    podman logs --tail 40 "$WEB" >&2 || true
    die "mattermost container exited during boot"
  fi
  [ "$i" = 180 ] && { podman logs --tail 40 "$WEB" >&2 || true; die "mattermost did not answer /api/v4/system/ping"; }
  sleep 1
done
log "mattermost is up"

api() { # method path token [json]
  local method=$1 path=$2 token=${3:-} body=${4:-}
  local args=(-sS -X "$method" -H 'Content-Type: application/json')
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  [ -n "$body" ] && args+=(--data "$body")
  curl "${args[@]}" "${URL}${path}"
}

jget() { python3 -c 'import json,sys; v=json.load(sys.stdin); print(v.get(sys.argv[1],""))' "$1"; }

# First user created on a fresh server becomes the system admin.
ADMIN=$(api POST /api/v4/users '' "{\"email\":\"$ADMIN_EMAIL\",\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
ADMIN_ID=$(printf '%s' "$ADMIN" | jget id)
[ -n "$ADMIN_ID" ] || { log "create admin: $ADMIN"; die "could not create the first user"; }
log "created admin $ADMIN_USER ($ADMIN_ID)"

# Login answers with the user object; the session token is the `Token` header.
ADMIN_TOKEN=$(curl -sS -D - -o /dev/null -X POST -H 'Content-Type: application/json' \
  --data "{\"login_id\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
  "${URL}/api/v4/users/login" | tr -d '\r' | awk 'tolower($1)=="token:"{print $2}')
[ -n "$ADMIN_TOKEN" ] || die "admin login failed"
log "admin logged in"

TEAM=$(api POST /api/v4/teams "$ADMIN_TOKEN" "{\"name\":\"arktest\",\"display_name\":\"Ark Test\",\"type\":\"O\"}")
TEAM_ID=$(printf '%s' "$TEAM" | jget id)
[ -n "$TEAM_ID" ] || { log "create team: $TEAM"; die "could not create team"; }
log "created team $TEAM_ID"

CHAN=$(api POST /api/v4/channels "$ADMIN_TOKEN" "{\"team_id\":\"$TEAM_ID\",\"name\":\"ark-e2e\",\"display_name\":\"Ark E2E\",\"type\":\"O\"}")
CHAN_ID=$(printf '%s' "$CHAN" | jget id)
[ -n "$CHAN_ID" ] || { log "create channel: $CHAN"; die "could not create channel"; }
log "created channel $CHAN_ID"

# The human peer: a normal account with a personal access token.
PEER=$(api POST /api/v4/users "$ADMIN_TOKEN" "{\"email\":\"$PEER_EMAIL\",\"username\":\"$PEER_USER\",\"password\":\"$PEER_PASS\"}")
PEER_ID=$(printf '%s' "$PEER" | jget id)
[ -n "$PEER_ID" ] || { log "create peer: $PEER"; die "could not create the peer user"; }

token_for() { # user_id -> personal access token
  api POST "/api/v4/users/$1/tokens" "$ADMIN_TOKEN" '{"description":"ark test"}' | jget token
}
PEER_TOKEN=$(token_for "$PEER_ID")
[ -n "$PEER_TOKEN" ] || die "could not create the peer access token"

# The bot: `POST /bots` creates the bot account itself (pre-creating a user
# with the same username makes the call fail with username_exists); posts made
# with it carry `props.from_bot`.
BOT=$(api POST /api/v4/bots "$ADMIN_TOKEN" "{\"username\":\"$BOT_USER\",\"display_name\":\"Ark Bot\",\"description\":\"ark integration test\"}")
BOT_ID=$(printf '%s' "$BOT" | jget user_id)
[ -n "$BOT_ID" ] || { log "create bot: $BOT"; die "could not create the bot account"; }
BOT_TOKEN=$(token_for "$BOT_ID")
[ -n "$BOT_TOKEN" ] || die "could not create the bot access token"

# A second bot, so the test can prove another bot's posts arrive with is_bot.
BOT2=$(api POST /api/v4/bots "$ADMIN_TOKEN" '{"username":"arkbot2","display_name":"Ark Bot 2","description":"other bot"}')
BOT2_ID=$(printf '%s' "$BOT2" | jget user_id)
[ -n "$BOT2_ID" ] || { log "create bot2: $BOT2"; die "could not create the second bot"; }
BOT2_TOKEN=$(token_for "$BOT2_ID")
[ -n "$BOT2_TOKEN" ] || die "could not create bot2's access token"

# Team membership first: a channel member must belong to the channel's team.
member_of() { # team_id user_id
  local out
  out=$(api POST "/api/v4/teams/$1/members" "$ADMIN_TOKEN" "{\"team_id\":\"$1\",\"user_id\":\"$2\"}")
  case $out in *'"user_id"'*|*already*|*'"status_code":409'*) return 0 ;; esac
  # Adding the creator (already a member) may answer 400/409; anything else is fatal.
  case $out in *'"id":"store.sql_team.save_member'*|*'"id":"api.team.add_member'*) log "team member: $out"; return 1 ;; esac
  return 0
}
member_of "$TEAM_ID" "$BOT_ID" || die "could not add the bot to the team"
member_of "$TEAM_ID" "$BOT2_ID" || die "could not add the second bot to the team"
member_of "$TEAM_ID" "$PEER_ID" || die "could not add the peer to the team"

# Both the bot and the peer must be channel members to post and to get WS events.
chan_member() { # channel_id user_id
  local out
  out=$(api POST "/api/v4/channels/$1/members" "$ADMIN_TOKEN" "{\"user_id\":\"$2\"}")
  case $out in *'"channel_id"'*|*already*) return 0 ;; esac
  log "channel member: $out"
  return 1
}
chan_member "$CHAN_ID" "$BOT_ID" || die "could not add the bot to the channel"
chan_member "$CHAN_ID" "$BOT2_ID" || die "could not add the second bot to the channel"
chan_member "$CHAN_ID" "$PEER_ID" || die "could not add the peer to the channel"

# Sanity: the bot token must work and the channel must be readable.
ME=$(api GET /api/v4/users/me "$BOT_TOKEN")
[ "$(printf '%s' "$ME" | jget id)" = "$BOT_ID" ] || { log "bot token /users/me: $ME"; die "bot token does not work"; }

cat <<EOF
export ARK_REAL_MATTERMOST_URL=$URL
export ARK_REAL_MATTERMOST_TOKEN=$BOT_TOKEN
export ARK_REAL_MATTERMOST_CHANNEL=$CHAN_ID
export ARK_REAL_MATTERMOST_TEAM=$TEAM_ID
export ARK_REAL_MATTERMOST_PEER_TOKEN=$PEER_TOKEN
export ARK_REAL_MATTERMOST_PEER_ID=$PEER_ID
export ARK_REAL_MATTERMOST_BOT_ID=$BOT_ID
export ARK_REAL_MATTERMOST_BOT2_TOKEN=$BOT2_TOKEN
export ARK_REAL_MATTERMOST_BOT2_ID=$BOT2_ID
EOF
if [ "$KEEP" = 1 ]; then
  log "stack ready; remove it with: $0 --down"
else
  log "stack ready (removing it on exit; pass --keep to keep it for the test)"
fi
