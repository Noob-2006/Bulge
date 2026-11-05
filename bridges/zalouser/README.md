# zalouser bridge

A Node sidecar that holds a Zalo **personal account** session through
[`zca-js`](https://github.com/RFS-ADRENO/zca-js) and exposes it to seagent's
`zalouser` channel over a bearer-protected HTTP API on loopback. zca-js call
shapes follow OpenClaw's `extensions/zalouser` (MIT).

Unofficial API: Zalo may restrict accounts used this way. Use a dedicated account.

## Install and run (manual; SE Agent never installs anything)

```sh
cd bridges/zalouser
npm install            # installs zca-js 2.2.0 only
ZALOUSER_BRIDGE_TOKEN=$(openssl rand -hex 24) \
ZALOUSER_DATA_DIR=$HOME/.local/state/seagent/zalouser \
node bridge.mjs
```

Environment:

| variable | default | meaning |
|---|---|---|
| `ZALOUSER_BRIDGE_TOKEN` | — (required, ≥16 chars) | bearer every request must carry |
| `ZALOUSER_BRIDGE_HOST` | `127.0.0.1` | listen address (keep it on loopback) |
| `ZALOUSER_BRIDGE_PORT` | `3920` | listen port |
| `ZALOUSER_DATA_DIR` | `./zalouser-data` | `<profile>.credentials.json` (mode 0600) and the QR PNG |
| `ZALOUSER_PROFILE` | `default` | session name inside the data dir |

On first start there are no credentials, so the bridge begins a QR login:
fetch `GET /qr` (a PNG data URL, also written to `<data>/<profile>.qr.png`) and
scan it with the Zalo app. The session cookies are saved and refreshed on each
login; later starts restore them. If the saved session is rejected the bridge
falls back to a new QR login. A closed listener reconnects with backoff.

## seagent config

```toml
[channels.zalo_me]
kind = "zalouser"
token = "{{secret:ZALOUSER_BRIDGE_TOKEN}}"
bridge_url = "http://127.0.0.1:3920"
# Optional: let seagent start and restart the sidecar (env vars are set for it).
command = ["node", "/opt/seagent/bridges/zalouser/bridge.mjs"]
# data_dir = "/var/lib/seagent/zalouser"   # default: seagent's state dir
# profile = "default"
allow = ["123456789"]
```

Chat ids: a DM is the peer's Zalo user id; a group is `g:<groupId>`.

## HTTP API

The listener runs with `selfListen` so our own sends are remembered (their
`cliMsgId` is needed to recall them); they are never queued as events.

Every request needs `Authorization: Bearer <ZALOUSER_BRIDGE_TOKEN>` (401 otherwise).
Responses are JSON. Errors are `{"error": "..."}` with: 400 bad input, 401 bad
bearer, 404 unknown route, 409 `not_logged_in` (scan the QR), 413 too large,
502 zca-js / Zalo failure (message passed through).

| method | path | body / query | response |
|---|---|---|---|
| GET | `/health` | | `{status, ownId, epoch, profile, queued}` |
| GET | `/qr` | | `{status, qr}` — `qr` is a PNG data URL while `status = "qr_pending"` |
| GET | `/messages` | `?after=<seq>&epoch=<epoch>&wait=<secs ≤60>` | `{epoch, ownId, status, events: [...]}` |
| POST | `/send` | `{threadId, isGroup, text, styles?, replyTo?}` — `styles`: zca-js `[{start, len, st, indentSize?}]` (UTF-16) | `{msgId}` |
| POST | `/send-media` | `{threadId, isGroup, kind: image\|video\|audio\|document, path? \| url?, filename?, caption?, styles?, replyTo?}` | `{msgId}` |
| POST | `/react` | `{threadId, isGroup, msgId, cliMsgId, icon, remove}` | `{ok}` |
| POST | `/typing` | `{threadId, isGroup}` | `{ok}` |
| POST | `/delete` | `{threadId, isGroup, msgId}` — own message: `undo` (recall); someone else's: group-admin `deleteMessage`; 404 if not among the last 500 seen | `{ok}` |
| GET | `/friends` | `?query=` (id / name substring; exact first) | `[{userId, displayName, avatar?}]` |
| GET | `/groups` | `?query=` | `[{groupId, name, memberCount?}]` |
| GET | `/me` | | `{userId, displayName, avatar?}` |
| POST | `/login` | | `{status}` — start a login (after a logout or declined QR) |
| POST | `/logout` | | `{ok}` — stop the listener and delete the saved credentials |

`status` is one of `starting`, `qr_pending`, `logged_in`, `reconnecting`, `logged_out`.

### Events

`/messages` long-polls: it returns every buffered event with `seq > after`,
waiting up to `wait` seconds for one. The bridge keeps the last 1000 events, so
a client that abandons a request loses nothing — it asks again with the same
`after`. `epoch` changes when the bridge restarts; a request with a different
epoch gets the whole buffer (client resets its cursor).

```json
{"seq": 12, "kind": "message", "type": 1, "threadId": "G1", "isSelf": false,
 "data": {"msgId": "…", "cliMsgId": "…", "uidFrom": "…", "idTo": "…", "dName": "Amy",
          "ts": "1700000000123", "msgType": "webchat", "content": "hi",
          "mentions": [{"uid": "…", "pos": 0, "len": 4}],
          "quote": {"ownerId": "…", "globalMsgId": 1, "msg": "…"}}}
```

`type` is zca-js `ThreadType` (0 user, 1 group); `data` is zca-js's raw message
data (`content` is a string for text, or `{href, title, description, thumb, params}`
for `chat.photo`, `chat.video.msg`, `chat.voice`, `share.file`, `chat.sticker`, links).
The bridge drops its own messages (`isSelf`).

`replyTo` quotes a message the bridge has seen recently (last 500). `/send-media`
with `kind = "audio"` uploads the file and sends it as a voice message (caption
first, as a separate text). Reaction `icon`s are Zalo codes (`/-strong`, `/-heart`,
`:>`, `:o`, `:-((`, `:-h`); SE Agent maps emoji to them.
