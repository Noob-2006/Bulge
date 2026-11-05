# Photon sidecar

A small Node process that bridges seagent's `kind = "photon"` channel to
[Photon](https://photon.codes)'s Spectrum SDK (`spectrum-ts`, TypeScript only),
which gives you an iMessage line without running your own Mac relay.

Adapted from the Hermes Agent Photon sidecar
(`plugins/platforms/photon/sidecar`, MIT License, Copyright (c) 2025 Nous
Research — see `LICENSE.hermes`). The only SE Agent change: requests may
authenticate with `Authorization: Bearer <token>` as well as the original
`X-Hermes-Sidecar-Token: <token>` header.

## Install (once)

SE Agent never installs packages for you:

```sh
cd bridges/photon
npm install          # Node 18.17+; the postinstall step patches spectrum-ts
```

You need a Photon project id and project secret (from the Photon dashboard,
or Hermes' `hermes photon setup`).

## Run

Let SE Agent supervise it:

```toml
[channels.imsg]
kind = "photon"
sidecar_dir = "/path/to/seagent/bridges/photon"
project_id = "…"
project_secret = "{{secret:PHOTON_PROJECT_SECRET}}"
port = 8789                     # loopback port of the sidecar
allow = ["+886912345678"]
```

SE Agent generates the shared token, spawns `node index.mjs` with
`PHOTON_PROJECT_ID`, `PHOTON_PROJECT_SECRET`, `PHOTON_SIDECAR_PORT`,
`PHOTON_SIDECAR_TOKEN` and `PHOTON_SIDECAR_BIND=127.0.0.1`, restarts it with
backoff when it exits and kills it when SE Agent stops (Linux: `PR_SET_PDEATHSIG`).

Or run it yourself and give SE Agent `sidecar_url` and `token`:

```sh
PHOTON_PROJECT_ID=... PHOTON_PROJECT_SECRET=... \
PHOTON_SIDECAR_PORT=8789 PHOTON_SIDECAR_TOKEN=$(openssl rand -hex 16) \
node index.mjs
```

## Loopback API

All requests need the token. Inbound is a long-lived NDJSON stream; the rest
are JSON POSTs answering `{"ok": true, …}` (or `{"ok": false, "error",
"error_class", "retryable"}`).

| Method | Path | Body → result |
|---|---|---|
| GET | `/inbound` | NDJSON events `{messageId, platform, space: {id, type, phone}, sender: {id}, content, timestamp}`; blank lines are heartbeats; one consumer at a time |
| POST | `/send` | `{spaceId, text, format: "text"\|"markdown"}` → `{messageId}` |
| POST | `/send-attachment` | `{spaceId, path, name?, mimeType?, caption?, kind: "attachment"\|"voice"}` → `{messageId}` |
| POST | `/send-richlink` | `{spaceId, url}` → `{messageId}` |
| POST | `/send-poll` | `{spaceId, title, options: [..≥2]}` → `{messageId}`; votes arrive as `poll_option` content |
| POST | `/send-effect` | `{spaceId, text, effect}` → `{messageId}` |
| POST | `/react` | `{spaceId, messageId, emoji}` → `{reactionId}` |
| POST | `/unreact` | `{spaceId, messageId, reactionId?}` |
| POST | `/unsend` | `{spaceId, messageId}` — retract one of our messages (seagent) |
| POST | `/typing` | `{spaceId, state: "start"\|"stop"}` |
| POST | `/healthz` | `{stream: …}` |
| POST | `/probe` | upstream liveness: `{alive: true}` or 503 |
| POST | `/shutdown` | exits after answering |

Content types on `/inbound`: `text`, `richlink`, `attachment` / `voice`
(bytes inlined as base64 `data` up to `PHOTON_MAX_INLINE_ATTACHMENT_BYTES`),
`group` (items), `reply` (wraps the content plus `targetMessageId`,
`targetDirection`, `targetText`), `reaction`, `read`, `poll`, `poll_option`.
