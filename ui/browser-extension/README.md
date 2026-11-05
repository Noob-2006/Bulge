# seagent browser relay (Chrome/Chromium extension)

A tiny Manifest V3 extension that lets a local `seagent` agent drive **your own** browser
tabs. It opens a WebSocket to `ws://127.0.0.1:<port>/extension`, authenticates with a
pairing token, and relays raw CDP JSON to `chrome.debugger` — so every seagent browser tool
works against the tabs you are already signed in to. Nothing leaves the machine: the
extension only talks to loopback.

Files: `manifest.json`, `background.js` (service worker), `options.html/js/css`,
`popup.html/js/css`. No build step, no external dependencies, no inline scripts.

## Install

1. Start the relay (it creates the token on first use):

   ```sh
   seagent browser extension
   # extension relay listening on 127.0.0.1:18792
   #   load ui/browser-extension as an unpacked extension, then paste this token …
   ```

   The token lives in `~/.local/share/seagent/browser/extension-token` (mode `0600`,
   24 characters). Keep the command running while SE Agent drives the browser.

2. Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked** and
   select this directory (`ui/browser-extension`).

3. Open the extension's **Settings** (toolbar icon → Settings, or
   `chrome://extensions` → Details → Extension options), set the port (default
   `18792`) and paste the contents of
   `~/.local/share/seagent/browser/extension-token` into **Pairing token**, then press
   **Save & connect**. The status line turns green once the relay answers
   `{"type":"welcome"}`.

4. Tell SE Agent to use it:

   ```toml
   [browser]
   backend = "extension"

   [browser.extension_control]
   enabled = true
   port = 18792          # 0 = 18792
   developer_mode = false # true also allows evaluate / raw CDP through the extension
   ```

   Then `seagent browser status` should report the extension as connected. Chrome shows a
   "…is debugging this browser" banner while SE Agent is attached — that is expected.

## How it works

```
seagent CDP client ──ws://127.0.0.1:P/cdp (Bearer token)──▶ relay ──▶ extension ──▶ chrome.debugger
```

- The extension reads `{port, token}` from `chrome.storage.local`, sends
  `{"type":"hello","token":…,"version":1,"userAgent":…}` and waits for
  `{"type":"welcome","version":1}`. A wrong token answers `{"type":"error"}` and closes
  with code `4401`; the extension then stops retrying until you fix the token.
- Reconnects use exponential backoff (1s → 2s → … → 30s) plus a `chrome.alarms` tick
  every 30s, because MV3 service workers get evicted.
- On `{"type":"attach"}` it attaches `chrome.debugger` to every attachable tab
  (`chrome://`, the Web Store, `devtools://` and other privileged pages are skipped) and
  enables `Page`/`Runtime` so events flow. On `{"type":"detach"}` it detaches everything.
- CDP frames are passed through as-is. `Target.getTargets`, `Target.attachToTarget`,
  `Target.detachFromTarget`, `Target.createTarget`, `Target.closeTarget`,
  `Target.activateTarget` and `Browser.getVersion` are answered by the extension from
  `chrome.tabs` (`targetId` is `String(tab.id)`); every other method is forwarded with
  `chrome.debugger.sendCommand` for the tab behind the frame's `sessionId`. Replies are
  `{"id":…,"result":…}` or `{"id":…,"error":{"code":-32000,"message":…}}`, echoing
  `sessionId` when the request had one. `chrome.debugger` events are sent back unwrapped
  as `{"method":…,"params":…}`.
- Connection state is mirrored to `chrome.storage.local` under `seagentStatus` and shown in
  the popup / options page.

## Limitations

- Chrome/Chromium (and Chromium-based Edge/Brave) only; Firefox's `chrome.debugger`
  equivalent is not wired up.
- Privileged pages (`chrome://`, `chrome-extension://`, the Web Store, PDF viewer
  internals) cannot be attached and are silently skipped.
- One seagent session at a time: the relay hands the single extension socket to the CDP
  client that connects to `/cdp`.
- The extension needs the `debugger` permission, so Chrome shows the debugging banner
  and a permission warning at install time.

## Troubleshooting

- **Status stays "Waiting for the relay"** — is `seagent browser extension` still running? Is the
  port the same as `browser.extension_control.port`? Another process may hold `18792`.
- **"bad token"** — the token is rotated whenever `extension-token` is deleted; re-copy the
  file. After a `4401` close the extension stops retrying, so it does not hammer the relay;
  press **Reconnect** in the options page once the token is fixed.
- **The relay address in the popup is grey and tabs show 0** — you are not paired yet, or the
  relay is not listening. `seagent browser status` prints the relay's view.
- Chrome may evict an idle MV3 service worker. The extension reconnects by itself: an
  exponential backoff while the worker is alive, and a 30-second `chrome.alarms` watchdog that
  re-establishes the socket (and re-attaches tabs on the next `attach`) after a restart.
- A tab that Chrome refuses to attach to (`chrome://…`, the Web Store, `devtools://`) is
  skipped silently; everything else in the window is driven normally.

## Credits

Protocol and behaviour were ported from the OpenClaw `extensions/browser/chrome-extension`
package (MIT licensed). This directory is an independent, dependency-free rewrite for
seagent's relay; see `THIRD_PARTY_NOTICES.md` in the repository root for the upstream notice.
