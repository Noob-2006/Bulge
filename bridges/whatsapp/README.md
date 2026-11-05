# WhatsApp (Baileys) bridge

A small Node.js process that links to a WhatsApp account as a "linked device"
(via [Baileys](https://github.com/WhiskeySockets/Baileys)) and exposes a
loopback HTTP API that seagent's `kind = "whatsapp"` channel talks to.

Adapted from the Hermes Agent bridge (`scripts/whatsapp-bridge`, MIT License,
Copyright (c) 2025 Nous Research — see `LICENSE.hermes`). SE Agent changes:

- optional shared bearer token: when `SEAGENT_WHATSAPP_BRIDGE_TOKEN` is set every
  request must send `Authorization: Bearer <token>` (seagent sets it when it
  supervises the bridge);
- `GET /qr` returns `{status, qr}` so the pairing QR can be shown elsewhere;
  `/health` also reports `qrPending`;
- default session / cache paths under `~/.seagent/` and no reply prefix.

## Install (once)

SE Agent never installs packages for you:

```sh
cd bridges/whatsapp
npm install          # Node 20+
```

## Pair

```sh
node bridge.js --pair-only --session ~/.seagent/whatsapp/session
```

Scan the QR code with WhatsApp → Settings → Linked devices. Credentials are
stored in the session directory. (While SE Agent supervises the bridge, `GET /qr`
returns the current QR payload if pairing is needed.)

## Run

Either let SE Agent supervise it:

```toml
[channels.wa]
kind = "whatsapp"
bridge_dir = "/path/to/seagent/bridges/whatsapp"   # seagent spawns `node bridge.js` here
session_dir = "~/.seagent/whatsapp/session"
mode = "bot"                                     # or "self-chat"
token = "{{secret:WA_BRIDGE_TOKEN}}"             # optional shared bearer token
allow = ["+886912345678"]
```

SE Agent restarts it with backoff when it exits and kills it when SE Agent stops
(Linux: `PR_SET_PDEATHSIG`). Or run it yourself and point SE Agent at it with
`bridge_url = "http://127.0.0.1:3000"` (no `bridge_dir`):

```sh
SEAGENT_WHATSAPP_BRIDGE_TOKEN=... node bridge.js --port 3000 --session ~/.seagent/whatsapp/session --mode bot
```

When supervised, SE Agent sets `WHATSAPP_ALLOWED_USERS=*`, `WHATSAPP_DM_POLICY=open`
and `WHATSAPP_GROUP_POLICY=open` unless you override them in `env`, because
seagent's own `allow` / `dm_policy` / `group_policy` decide who is answered.

## HTTP API (127.0.0.1 only)

| Method | Path | Body / result |
|---|---|---|
| GET | `/messages` | queued inbound events (array; drained on read) |
| POST | `/send` | `{chatId, message, replyTo?, mentions?}` → `{messageId, messageIds}` |
| POST | `/edit` | `{chatId, messageId, message}` |
| POST | `/delete` | `{chatId, messageId}` — revoke for everyone (seagent) |
| POST | `/react` | `{chatId, messageId, emoji}`, `""` removes (seagent) |
| POST | `/send-media` | `{chatId, filePath, mediaType?, caption?, fileName?}` |
| POST | `/send-poll` | `{chatId, question, options, selectableCount?}` |
| POST | `/send-location` | `{chatId, latitude, longitude, name?, address?}` |
| POST | `/typing` | `{chatId}` |
| POST | `/read` | `{key}` (honoured when `WHATSAPP_SEND_READ_RECEIPTS=true`) |
| GET | `/chat/:id` | `{name, isGroup, participants}` |
| GET | `/health` | `{status, queueLength, qrPending, uptime, scriptHash, session}` |
| GET | `/qr` | `{status, qr}` |

Useful environment variables (see the top of `bridge.js`): `WHATSAPP_MODE`,
`WHATSAPP_ALLOWED_USERS`, `WHATSAPP_GROUP_ALLOWED_USERS`,
`WHATSAPP_DM_POLICY`, `WHATSAPP_GROUP_POLICY`, `WHATSAPP_SEND_READ_RECEIPTS`,
`WHATSAPP_MAX_MESSAGE_LENGTH`, `WHATSAPP_SEND_TIMEOUT_MS`,
`HERMES_IMAGE_CACHE_DIR` / `HERMES_DOCUMENT_CACHE_DIR` / `HERMES_AUDIO_CACHE_DIR`
(where inbound media is written; SE Agent sets them under its state directory).
