# SE Agent on Android and iOS

Same Tauri project as the desktop app (`apps/desktop`), mobile targets. The mobile projects
(`src-tauri/gen/android`, `src-tauri/gen/apple`) are generated, not committed; everything custom
lives in committed files and is applied by scripts, so `init` can be re-run at any time.

| | Android | iOS |
|---|---|---|
| Runs the agent itself | yes — `libseagent.so daemon run` under a Foreground Service | **no** (no VM, no local shell, no subprocesses: platform policy) |
| Connect to a host on the LAN | yes ("connect to another computer") | yes — the only mode |
| Discovery | NsdManager `_seagent._tcp` (+ multicast lock) | NWBrowser `_seagent._tcp` (Bonjour) |
| Pairing | QR (`seagent-pair://…` setup code) or address + 8-character code | same |
| Transport to a host | pinned TLS (SHA-256 of the host certificate) through a loopback tunnel | same |

**iOS limitation, stated in the app (connect screen) and the README:** iPhone/iPad builds are a
client of a paired SE Agent host. There are no VMs and no local shell on iOS; work that needs them
runs on the paired computer. Chat, notifications and files work whenever that host is reachable.

## How the pieces fit

- `src/index.html` (splash) → on Android asks once "run it on this phone" / "connect to another
  computer" (`set_mode`); iOS goes straight to `src/connect.html`.
- **Local (Android)**: `boot.rs` asks the plugin for `{exe, env}` (`info`: nativeLibraryDir +
  `SEAGENT_HOME=files/seagent`, `SEAGENT_SHARE_DIR=files/share`, `TMPDIR`, `XDG_RUNTIME_DIR=""`),
  runs `setup bootstrap`, starts `AgentService` (`startAgent`), waits for
  `http://127.0.0.1:8640/health`, then opens the wizard or console exactly like the desktop.
  The service restarts the agent when it exits (including the planned exit after the wizard
  applies a config) and survives reboots when "start automatically" is ticked (`BootReceiver`).
- **Remote (both)**: `connect.html` lists paired hosts, discovers new ones, scans a QR code
  (`tauri-plugin-barcode-scanner`) or takes address + code. The host's certificate fingerprint is
  pinned from the QR code, or — for the typed code — shown on both screens for the user to compare
  (and checked against the `fp` prefix the host announces over mDNS). `pair_host` then calls the
  host's `POST /pair/client` over pinned TLS and stores `{address, fingerprint, consoleToken}` in
  the app data dir. `host_open` starts a loopback listener (`127.0.0.1:<stable port>`) that
  forwards every connection over pinned TLS to the host and loads
  `http://127.0.0.1:<port>/#token=<consoleToken>` in the WebView — so WKWebView / Android WebView
  never deal with a self-signed certificate, and nothing leaves the device unencrypted.

## Prerequisites

| | Needed |
|---|---|
| Both | Rust stable, Tauri CLI 2 (`cargo install tauri-cli --version '^2' --locked`) |
| Android | JDK 17, Android SDK (platform 36, build-tools), NDK r26+ (`ANDROID_HOME`, `NDK_HOME`/`ANDROID_NDK_HOME`), `rustup target add aarch64-linux-android` |
| iOS | macOS with Xcode 15+, CocoaPods not required, `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`; an Apple Developer team for device / TestFlight builds |

## Android build

```bash
cd apps/desktop
cargo tauri android init                  # generates src-tauri/gen/android (once, or after upgrades)
cargo tauri icon ../../ui/icon.svg && git checkout -- src-tauri/icons   # launcher icons
scripts/prepare-android.sh                # builds seagent for aarch64-linux-android with the NDK,
                                          # installs it as jniLibs/arm64-v8a/libseagent.so,
                                          # copies share/ to assets, patches gradle + manifest
cargo tauri android build --apk --target aarch64            # release (sign it, see below)
cargo tauri android build --apk --target aarch64 --debug    # debug-signed, installs directly
cargo tauri android dev                   # on a device/emulator (arm64)
```

What `prepare-android.sh` changes in the generated project (idempotent):

1. `app/build.gradle.kts`: `packaging { jniLibs { useLegacyPackaging = true } }` — the agent is an
   **executable** shipped as `libseagent.so`; Android only allows exec from `nativeLibraryDir`
   (W^X since Android 10) and only extracts the file there with legacy packaging.
2. `AndroidManifest.xml` `<application>`: `android:extractNativeLibs="true"` and
   `android:networkSecurityConfig="@xml/seagent_network_security"` (cleartext only to
   127.0.0.1/localhost; the resource ships with the plugin).

Everything else comes from the plugin library (`plugins/seagent-mobile/android`), whose manifest is
merged automatically: permissions `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`,
`CHANGE_WIFI_MULTICAST_STATE` (mDNS), `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`,
`POST_NOTIFICATIONS`, `RECEIVE_BOOT_COMPLETED`, `WAKE_LOCK`; the `AgentService`
(`foregroundServiceType="specialUse"` with a subtype description — Play review needs that text)
and `BootReceiver`. The QR scanner plugin adds `CAMERA`.

Release signing: `apksigner sign --ks release.jks …` on the `*-unsigned.apk` (CI does it when the
`ANDROID_KEYSTORE*` secrets exist), or configure `signingConfigs` in the generated gradle file.

Only arm64-v8a is bundled (the agent binary); 32-bit and x86_64 emulators can still use
"connect to another computer" if you add those Rust targets to the app build.

## iOS build

```bash
cd apps/desktop
cargo tauri ios init                      # generates src-tauri/gen/apple
cargo tauri icon ../../ui/icon.svg && git checkout -- src-tauri/icons
cargo tauri ios dev                       # simulator or a connected device
cargo tauri ios build --target aarch64-sim --debug          # unsigned simulator build (CI does this)
cargo tauri ios build --export-method app-store-connect     # needs bundle.iOS.developmentTeam or APPLE_DEVELOPMENT_TEAM
```

`src-tauri/Info.ios.plist` is merged into the generated Info.plist: `NSLocalNetworkUsageDescription`,
`NSBonjourServices = [_seagent._tcp]`, `NSCameraUsageDescription` (QR), and ATS
`NSAllowsLocalNetworking` (the console is loaded from the app's own loopback tunnel). iOS asks for
local-network permission the first time the app browses; if the user declines, discovery returns
nothing and the typed-address flow still works after allowing it in Settings › Privacy › Local Network.

The Swift side (`plugins/seagent-mobile/ios`) only does discovery; TLS pinning, pairing and the
tunnel are shared Rust (`src-tauri/src/tls.rs`, `pair.rs`).

## Agent-side changes needed

The app is written against these; they are not in the agent yet (other workstreams: LAN, binary):

1. **`POST /pair/client`** on the App Server (TLS, LAN mode), served before the app-token check:
   request `{"bootstrapToken": "…"}` *or* `{"code": "ABCD2345"}`, plus
   `{"device": {"id": "<32 hex, stable per install>", "name": "…", "platform": "ios|android|…"}}`;
   response `200 {"consoleToken": "…", "hostId": "…", "name": "<host name>"}`, errors
   `4xx {"error": "…"}`. The bootstrap token is the one in the setup code (single use); the code
   is a short-lived 8-character code (alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, like node
   pairing) shown on the host. `consoleToken` is a **per-device, revocable** console credential the
   web console accepts in `#token=` (listed and revocable next to nodes), never the admin
   `APP_TOKEN`. Rate-limit and audit failures.
2. **`seagent pair code [--json] [--ttl MIN]`** (and a "Devices" page in the console): shows the QR
   (`seagent-pair://` + base64url `{url: "wss://<lan-ip>:<port>/node", bootstrapToken, expiresAtMs,
   tlsFingerprint}`), the 8-character code and the short fingerprint (first 16 hex digits, grouped
   by four — the app shows the same).
3. **TLS fingerprint** = SHA-256 over the DER leaf certificate in `<data>/tls/`, lower-case hex
   (what `normalize_fingerprint` already accepts).
4. **mDNS** `_seagent._tcp.local` with TXT `v=<protocol>`, `id=<host id>`, `fp=<first 16 hex of the
   fingerprint>` (no tokens), only in LAN mode.
5. **Origin/Host through the tunnel**: the WebView sends `Host: 127.0.0.1:<local port>` and
   `Origin: http://127.0.0.1:<local port>` over the TLS connection from a LAN address. The server's
   `origin_allowed(origin, host)` (same-origin) accepts that today; any future Host allow-list for
   LAN mode must keep accepting loopback Host headers on authenticated TLS connections.
6. **Android port of the agent** (`aarch64-linux-android`): daemon socket under `SEAGENT_HOME` when
   `XDG_RUNTIME_DIR` is empty, graceful exit on SIGTERM (the service stops it that way), the
   wizard's autostart step reporting "handled by the app" on Android (the app syncs its
   `BootReceiver` through `autostart_set`), shell `/system/bin/sh`.
7. Desktop: `seagent setup status --json` and `seagent app token --json` (see README.md here).
