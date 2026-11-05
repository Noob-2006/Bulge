# ark sandbox browser (Chromium + noVNC)

Containerimage for the `sandbox` browser backend (`crates/ark-browser/src/sandbox.rs`).
ark runs it with `docker run` (or `podman run`) with `-d --rm --init --network <bridge> -p 127.0.0.1::9222 [-p 127.0.0.1::6080]`
and talks CDP to the **relay** on 9222 with `Authorization: Basic base64("ark:<token>")`.

Ported from OpenClaw `scripts/sandbox-browser-entrypoint.sh`,
`scripts/sandbox-browser-setup.sh` and `scripts/docker/sandbox/Dockerfile.browser` (MIT);
the `OPENCLAW_*` environment contract was replaced by `ARK_BROWSER_*`.

## Build

```bash
docker build -t ark-sandbox-browser:trixie-slim packaging/sandbox-browser
# podman works too (rootless is fine; add --network=host if the build cannot resolve DNS):
podman build --network=host -t ark-sandbox-browser:trixie-slim packaging/sandbox-browser
```

ark resolves the CLI itself: `ARK_DOCKER`, else `docker`, else `podman`
(`sandbox::docker()` in `crates/ark-browser/src/sandbox.rs`). Before this the backend
silently disappeared on podman-only machines, because only `docker` was probed.

`tests/real/sandbox_browser_up.sh` builds the image if it is missing, verifies the
contract label, and prints the env the real test needs:

```bash
eval "$(./tests/real/sandbox_browser_up.sh)"      # or --rebuild / --down
cargo test -p ark-browser --test real_sandbox_browser
```

### Verified against a real container (2026-11-05)

Built with podman from this directory (`debian:trixie-slim`, Chromium **156.0.8078.79**,
~1 min 50 s, 1.02 GB) and driven end to end by
`crates/ark-browser/tests/real_sandbox_browser.rs` (3 tests, ~4 s):

| Test | What the real container proved |
| ---- | ------------------------------ |
| `drives_a_real_chromium_inside_the_sandbox_container` | `Manager::browser(backend="sandbox")` starts Xvfb + Chromium + relay + noVNC; a real HTTP page loads inside the container, its `<script>` runs (`js-ran:42`), a 1280×800 PNG screenshot comes back, noVNC `/vnc.html` answers 200, the browser runs as uid 1000 `ark`, and `b.close()` removes the container |
| `headless_sandbox_browser_has_no_novnc_and_still_works` | `ARK_BROWSER_HEADLESS=1` ⇒ no Xvfb/x11vnc/noVNC, port 6080 unpublished, `--headless=new` in `navigator.userAgent`, same auth gate |
| `the_built_image_carries_the_contract_label` | the built image really carries `org.ark.sandbox-browser.contract=2026-11-cdp-relay-auth` and the expected ENTRYPOINT |

The relay was also probed directly from the host: `/json/version` without credentials and
with a wrong token both answer `401`; with ark's token `200`; `docker port <container> 9223`
is empty, i.e. Chromium's own DevTools port never reaches the host.

Without a container CLI (or without `ARK_REAL_SANDBOX_IMAGE`) the tests skip and pass;
`cargo test -p ark-browser sandbox::` still checks the image sources statically (contract
label, ports, env names, `bash -n`, executable bit, and that the entrypoint fails closed
without a token).

## Configure

```toml
[browser]
backend = "sandbox"

[browser.sandbox]
image = "ark-sandbox-browser:trixie-slim"  # default: ark-sandbox-browser:latest
network = "bridge"                         # "host" is refused by ark
novnc = true                               # publish the noVNC observer port
headless = false                           # true = Chromium --headless=new, no Xvfb/noVNC
start_timeout_ms = 12000                   # CDP must answer within this window
```

Then `ark` (or a tool call) with a browser-backed command starts the container lazily and
removes it (`<cli> rm -f`) when the session closes or startup fails.

For a local TLS-less registry / podman socket, set `ARK_DOCKER` to the CLI you use
(`ark doctor` then reports e.g. `browser: sandbox (podman at /usr/bin/podman)`).

## Image contract label

The image stamps:

```
LABEL org.ark.sandbox-browser.contract="2026-11-cdp-relay-auth"
```

ark inspects that label before the `run` and refuses a missing/mismatched value
(`Sandbox browser image ... is stale or incompatible`), so an old image can never be
paired with a newer entrypoint. Bump the constant `CONTRACT` in
`crates/ark-browser/src/sandbox.rs` and the `LABEL` here in the same commit whenever the
environment contract changes.

## Ports

| Host (loopback only)        | Container | What it is |
| --------------------------- | --------- | ---------- |
| `-p 127.0.0.1::9222`        | 9222      | CDP relay: Basic `ark:<token>` required, else `401` |
| `-p 127.0.0.1::6080`        | 6080      | noVNC (`/vnc.html`) via websockify → 127.0.0.1:5900 |
| – (never published)         | 9223      | Chromium's own CDP port, bound to 127.0.0.1 only |
| – (never published)         | 5900      | x11vnc, `-localhost` + VNC password |

Chromium is never reachable without the relay, and the relay listens on 9222 only after
ark supplies `ARK_BROWSER_CDP_AUTH_TOKEN`.

## Environment contract

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `ARK_BROWSER_CDP_AUTH_TOKEN` | *(required)* | Relay credential; empty ⇒ warning + exit 1 (fail closed) |
| `ARK_BROWSER_CDP_PORT` | `9222` | Relay listen port |
| `ARK_BROWSER_CHROME_CDP_PORT` | `9223` | Chromium `--remote-debugging-port` (loopback) |
| `ARK_BROWSER_CDP_SOURCE_RANGE` | *(empty)* | Optional CIDR allow-list for relay clients |
| `ARK_BROWSER_HEADLESS` | `0` | `1` ⇒ `--headless=new`, no Xvfb/x11vnc/noVNC |
| `ARK_BROWSER_ENABLE_NOVNC` | `1` | `1` ⇒ x11vnc + websockify (ignored when headless) |
| `ARK_BROWSER_NOVNC_PASSWORD` | *(random)* | VNC password; random 8 chars when unset |
| `ARK_BROWSER_VNC_PORT` / `ARK_BROWSER_NOVNC_PORT` | `5900` / `6080` | x11vnc / websockify ports |
| `ARK_BROWSER_NO_SANDBOX` | `0` | `1` ⇒ add `--no-sandbox --disable-setuid-sandbox` (ark passes `1`) |
| `ARK_BROWSER_AUTO_START_TIMEOUT_MS` | `12000` | Startup deadline for Xvfb/CDP/relay |

Other knobs: `ARK_BROWSER_DISABLE_GRAPHICS_FLAGS`, `ARK_BROWSER_DISABLE_EXTENSIONS`,
`ARK_BROWSER_RENDERER_PROCESS_LIMIT`, `ARK_BROWSER_PROFILE_DIR`, `ARK_BROWSER_CHROMIUM`,
`ARK_BROWSER_DISPLAY`. All numeric values are validated (`^[0-9]+$`, range-checked).

On any startup failure the entrypoint prints the tail of `/tmp/ark-browser/sandbox.log`
and exits non-zero, so `docker logs`/ark's error message shows the real Chromium error.

## Watching the session (noVNC)

The browser's `novnc_url` (in `view.browser.list`) is loopback-only and carries the
per-container VNC password, so it is not meant to be handed to a client directly.
Get a **one-time ticket** instead:

- RPC `view.novnc {key: "sandbox", open: true}` → `{url}`; or `{open: false}` → `{ticket, path, expiresAtMs}`
- HTTP `POST /view/novnc` → same JSON; then `GET /view/novnc?ticket=<ticket>` (60 s TTL,
  single use) serves the bootstrap page that loads the noVNC viewer.

## Notes

- Nothing here uses host networking; `network = "host"` is rejected by ark before `run`.
- The container does not run privileged, does not mount the host, and drops to the
  non-root user `ark` (Chromium's setuid sandbox helper stays usable; ark still passes
  `ARK_BROWSER_NO_SANDBOX=1` for hosts without user namespaces).
