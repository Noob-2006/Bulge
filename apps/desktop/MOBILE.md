# SE Agent on Android and iOS

Same Tauri project as the desktop app (`apps/desktop`), mobile targets. The mobile projects
(`src-tauri/gen/android`, `src-tauri/gen/apple`) are generated, not committed; everything custom
lives in committed files and is applied by scripts, so `init` can be re-run at any time.

| | Android | iOS |
|---|---|---|
| Runs the agent itself | yes — `libseagent.so daemon run` under a Foreground Service | **yes — in the app process** (`seagent::embed`, linked into the app; iOS allows no child processes) |
| Commands (shell tool) | `/system/bin/sh` + toybox, Landlock | **WASM sandbox**: WASI tools in the wasmi interpreter + built-in POSIX shell (`exec.backend = "wasm"`) |
| VMs | AVF where the device has it | **none** (no hypervisor for apps — platform policy) |
| In the background | Foreground Service (always on) | foreground only; cron / heartbeat via BGProcessingTask (when iOS allows) |
| Connect to a host on the LAN | yes ("connect to another computer") | yes — **optional** |
| Discovery | NsdManager `_seagent._tcp` (+ multicast lock) | NWBrowser `_seagent._tcp` (Bonjour) |
| Pairing | QR (`seagent-pair://…` setup code) or address + 8-character code | same |
| Transport to a host | pinned TLS (SHA-256 of the host certificate) through a loopback tunnel | same |

**iOS, stated in the app (splash and connect screen), the README and docs/cross-platform.md:** SE
Agent is serverless and self-hosted, so on iPhone/iPad it runs *on the phone*: kernel, sessions,
model providers, memory, skills, web fetch/search, file tools in the app sandbox, MCP over
Streamable HTTP/SSE (no stdio servers — they would be child processes), chat channels (pure network
clients), schedules and the App Server on 127.0.0.1 whose console the WebView loads. Only two things
are unavailable: **virtual machines** and **native shell programs**. Commands run in the in-process
WebAssembly sandbox instead (workspace and a private `/tmp` only, no network, pinned tools). Work
that truly needs a VM or a native toolchain can go to a paired computer.

## How the pieces fit

- `src/index.html` (splash) → on Android asks once "run it on this phone" / "connect to another
  computer" (`set_mode`). iOS runs the agent on the phone by default (`mode()` = local unless the
  user picked a computer), shows the iOS notice and a "connect to another computer instead" link.
- **Local (iOS)**: `boot.rs` asks the plugin to `start_local`: Swift `agentEnv` returns
  `{home: <Application Support>/seagent, share: <bundle>/share, vaultKey: <Keychain>}`, then
  `seagent::embed::start` sets `SEAGENT_HOME`, `SEAGENT_VAULT_KEY`, `SEAGENT_SHARE_DIR`, runs
  `setup bootstrap` in-process and starts the daemon assembly on background threads (no control
  socket). It returns the App Server's address and the one-time setup link (first run) or the
  console URL with its token, which the WebView opens — the same pages as on a desktop. After the
  wizard applies a configuration the embedded daemon restarts itself in-process.
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
| iOS | macOS with Xcode 15+, CocoaPods not required, `rustup target add aarch64-apple-ios aarch64-apple-ios-sim wasm32-wasip1` (the last one builds the WASI tools); an Apple Developer team for device / TestFlight builds |

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
scripts/prepare-ios.sh                    # WASI tools → src-tauri/wasi-tools (bundled as share/wasi)
cargo tauri ios dev                       # simulator or a connected device
cargo tauri ios build --target aarch64-sim --debug          # unsigned simulator build (CI does this)
cargo tauri ios build --export-method app-store-connect     # needs bundle.iOS.developmentTeam or APPLE_DEVELOPMENT_TEAM
```

The agent is not a separate build step on iOS: `plugins/seagent-mobile/Cargo.toml` depends on the
`seagent` library (`crates/seagent`) for `target_os = "ios"` only, so `cargo tauri ios build`
compiles the whole agent (`aarch64-apple-ios` / `aarch64-apple-ios-sim`) into the app's static
library. The exec backend `wasm` (wasmi) is always on for iOS.

`src-tauri/Info.ios.plist` is merged into the generated Info.plist: `NSLocalNetworkUsageDescription`,
`NSBonjourServices = [_seagent._tcp]`, `NSCameraUsageDescription` (QR), ATS
`NSAllowsLocalNetworking` (the console is loaded from 127.0.0.1: the in-app App Server, or the
loopback tunnel to a paired host), `BGTaskSchedulerPermittedIdentifiers = [dev.seagent.agent.refresh]`
and `UIBackgroundModes = [processing, fetch]`. iOS asks for local-network permission only the first
time the app browses for a computer; the local agent itself needs none (loopback).

The Swift side (`plugins/seagent-mobile/ios`): `agentEnv` (home, bundled share/, Keychain vault key
— created on first use, `kSecAttrAccessibleAfterFirstUnlock` so a background task can open the
vault), `scheduleBackground`, BGTaskScheduler registration and the foreground / background
observers, and discovery. It calls the Rust side through four C functions exported by the plugin
crate (`seagent_mobile_bg_run`, `_bg_expired`, `_next_due`, `_foreground`). TLS pinning, pairing and
the tunnel are shared Rust (`src-tauri/src/tls.rs`, `pair.rs`).

### Commands on iOS: the WASM sandbox

There is no `fork`/`exec` on iOS, no JIT (so no wasmtime / V8) and no hypervisor. The shell tool
therefore runs in `exec.backend = "wasm"` (`crates/seagent-tools/src/exec/wasm/`):

- the command line is interpreted by a built-in POSIX-ish shell (pipelines, `&&`/`||`, subshells,
  `if`/`for`/`while`/`case`, functions, redirections and here-documents, `$(…)`, `$((…))`, globs,
  `cd`/`export`/`test`/`printf`/`read`/… builtins) — dash or busybox ash cannot work there, they
  need `fork`;
- every external command is a `wasm32-wasip1` module from the tools directory, run by wasmi (pure
  Rust interpreter). WASI preview 1 is implemented in the agent: the module sees only the
  workspace (read-only when the sandbox says so), a private `/tmp` and configured binds; `..` and
  symlinks cannot leave them; there are no sockets; a fuel budget makes timeouts and interrupts
  take effect, and linear memory is capped (`[exec.wasm] memory_mb`, default 512);
- the tools (`scripts/build-wasi-tools.sh`, everything from pinned sources with `--locked`):
  **uutils coreutils 0.12.0** (`feat_wasm`: 78 commands — ls, cat, cp, mv, rm, mkdir, head, tail,
  sort, uniq, wc, cut, tr, tee, seq, date, sha256sum, base64, …), **uutils sed 0.3.0**, **uutils
  findutils 0.11.0** `find` (its Oniguruma regex engine is C, compiled with the pinned wasi-sdk),
  and **grep** from `tools/wasi-grep` (POSIX `-E/-F/-G -i -v -n -c -l -L -o -q -s -w -x -r -e -f`,
  `-A/-B/-C`, `-m`, `--include/--exclude`; `egrep`/`fgrep` too). `xargs` is a shell builtin (a
  WASI xargs could not start the command); `find -exec` cannot work for the same reason — use
  `find … | xargs …`. `tools.json` pins every module's SHA-256; a mismatch, or a module the
  manifest does not pin, is refused at run time. `prepare-ios.sh` puts the set (≈47 MB with
  Python) in `src-tauri/wasi-tools`, which `tauri.ios.conf.json` bundles as `share/wasi`.
- isolation is reported honestly (`seagent sandbox explain`): OS-sandbox tier, "wasm interpreter
  sandbox" — the wall is enforced by the interpreter in the app's own process.

**Python** — `scripts/build-wasi-python.sh` builds **CPython 3.14.10** for `wasm32-wasip1` from the
python.org source tarball with **wasi-sdk 24** (the version CPython's `Tools/wasm/wasi` supports)
from the official WebAssembly/wasi-sdk release; both downloads are pinned by SHA-256
(`scripts/wasi-sdk.sh`, the script header) and refused on a mismatch. It runs CPython's own cross
build (no wasmtime needed), strips the module (7.4 MB), ships a trimmed, precompiled standard
library (no tests, tkinter, idlelib, ensurepip, venv) and adds `python3` / `python` to
`tools.json` with the module digest and the stdlib mounted read-only at
`/usr/local/lib/python3.14`. Scripts run with the same walls as every tool: the workspace and
`/tmp` only, no sockets (so no `pip install` from the network, no `urllib` downloads), no
threads or subprocesses (WASI preview 1). `crates/seagent-tools/tests/wasm_backend.rs` runs real
scripts through it (stdlib imports, file I/O in the workspace, exit codes, escape attempts).

### Background on iOS

The agent runs while the app is in the foreground (and for the short grace iOS gives after it
leaves, so a reply in flight can finish). Going to the background books a `BGProcessingTask`
(`dev.seagent.agent.refresh`) at the next due cron job, at least 15 minutes ahead; when iOS runs
it, the plugin starts the agent if the app was launched just for the task, lets the scheduler
claim what came due, and waits up to ~4 minutes for those runs (`seagent::embed::background_pass`).
iOS decides when the task really runs (typically on power, network, idle), may skip it, and stops
it at its deadline (the plugin then interrupts; open turns resume on the next start). So on iOS
schedules are best effort, chat channels only answer while the app is open or a task is running,
and webhooks/inbound connections need the app in the foreground — a paired always-on computer, or
Android, is the answer when that matters. Returning to the foreground re-checks the App Server and
restarts the agent if iOS reclaimed its listening socket.

## Agent-side contract

Items 1–5 are implemented in the agent (branch `xp/lan`: `crates/seagent-app/src/{devices,lan}.rs`,
`crates/seagent-net/src/{x509,mdns}.rs`; protocol in `docs/arp.md`):

1. **`POST /pair/client`** on the App Server (TLS, LAN mode), served before the app-token check:
   request `{"bootstrapToken": "…"}` *or* `{"code": "ABCD2345"}`, plus
   `{"device": {"id": "<32 hex, stable per install>", "name": "…", "platform": "ios|android|…"}}`;
   response `200 {"consoleToken": "…", "hostId": "…", "name": "<host name>", "deviceId", "scope"}`,
   errors `4xx {"error": "…"}`. The bootstrap token is the one in the setup code (single use).
   **Change from the first proposal:** a typed 8-character code only *requests* pairing — the host
   answers `202 {"status": "pending", "requestId", "retryAfterMs", "expiresAtMs", "sas"}` (after
   long-polling up to 15 s) until an admin approves it; the app re-posts the same body plus
   `requestId` until `200` (or `403` rejected / expired). `pair_host` does this (15 min cap).
   `consoleToken` (`sed1_…`) is a **per-device, revocable** console credential the web console
   accepts in `#token=`, never the admin `APP_TOKEN`; it is the *only* credential LAN peers may use.
   Rate-limited and audited.
2. **`seagent pair code [--json] [--ttl MIN] [--scope write|admin]`** (and "Devices → Pair a device"
   in the console): shows the QR — now the link `https://<lan-ip>:<port>/#setup=<setup code>` so a
   plain phone camera opens the console and pairs; `SetupCode::decode` accepts that form as well as
   `seagent-pair://<code>` — the 8-character code and the short fingerprint (first 16 hex digits,
   grouped by four — the app shows the same).
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
8. **iOS in-process agent** (`crates/seagent/src/embed.rs`): `start(Options{home, vault_key,
   share_dir, workspace, set})` → `Console{base, url, setup}` once the App Server accepts
   connections; `console()`, `stop(limit)`, `running()`, `next_due()`, `background_pass(budget)`.
   It is `daemon_cli::run` with `Ipc::Off` — tested for real on Linux by
   `crates/seagent/tests/embed_inprocess.rs`.
