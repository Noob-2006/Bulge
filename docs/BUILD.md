# Build layers, cargo features and what a slim binary costs

Audit row **D6** (binary size / build cost). The default `seagent` release binary is ~33 MB:
every optional chat platform, every model adapter and every media subsystem is compiled
in. This document describes the layers that exist, the exact commands for the default,
slim and smallest builds, the measured sizes, and the size budget that keeps them from
creeping.

Everything here is measured, not estimated. The 2026-11-05 numbers were taken on Linux
x86_64 in one **clean target directory** (so every configuration was compiled from the
same tree state and the deltas are comparable), with the workspace release profile
(`opt-level = "s"`, `lto = true`, `codegen-units = 1`, `strip = true`, `panic = "abort"`)
unless noted.

## TL;DR

| Build | Command | Size | vs default |
| --- | --- | --- | --- |
| default (everything) | `cargo build -p seagent --release` | 33 694 024 B (32.13 MiB) | — |
| slim features | `cargo build -p seagent --release --no-default-features` | 29 543 848 B (28.17 MiB) | **−4 150 176 B (−12.3 %)** |
| slim profile (same code) | `cargo build -p seagent --profile slim` | 28 947 688 B (27.61 MiB) | **−4 746 336 B (−14.1 %)** |
| smallest | `cargo build -p seagent --profile slim --no-default-features` | 25 474 120 B (24.29 MiB) | **−8 219 904 B (−24.4 %)** |

Only two of these change what is compiled; the third row runs the *same* code with
`opt-level = "z"` (see [The three levers](#the-three-levers-measured-separately)).

`--no-default-features` still produces a working binary: it starts, parses config and runs
everything except the channels and model adapters whose cargo feature is off. Configuring
such a channel is not an error — it is skipped with a warning:

```
$ SEAGENT_HOME=$TMPDIR/home-slim ./target/release/seagent channel list      # slim binary
seagent: warning: channel kind `slack` is not compiled into this build (cargo feature `slack` is off; see docs/BUILD.md)
no channels (configure [channels.<name>] kind = "telegram", "discord", "slack", "line"… — see docs/config-example.toml)

$ SEAGENT_HOME=$TMPDIR/home-slim ./target/release/seagent channel list      # default binary, same config
s                slack          dm: Allowlist · allow: (nobody — set allow)
```

The same holds for a model adapter that is not compiled in — the wire format stays a
valid config value, only `build` refuses:

```
provider `bedrock`: the `bedrock` wire format is not compiled into this build
(cargo feature `bedrock` of seagent-model is off; see docs/BUILD.md)
```

Kinds still available in a slim build: `telegram`, `webhook`, `discord`, `msteams`,
`teams`, `msgraph_webhook`, `whatsapp`, `whatsapp_cloud` (everything in the
"cannot be gated" table below).

## The three levers, measured separately

| Lever | What is removed | Measured delta |
| --- | --- | --- |
| chat platforms (`--no-default-features` with `providers` still on) | the 24 optional platform families of `seagent-channel` | −4 150 176 B (−12.3 %) |
| model adapters (`providers` off) | Bedrock/SigV4, Gemini, agent CLIs, Agents API, managed llama.cpp | −2 368 B (±0.01 %, i.e. **not a size lever** — see below) |
| `opt-level = "z"` (`--profile slim`, all features) | nothing; same code, size-first codegen | −4 746 336 B (−14.1 %) |
| all of the above | everything optional, size-first codegen | −8 219 904 B (−24.4 %) |

Two honest caveats:

* **Measurement noise.** LTO lays sections out differently on every build; the same tree
  re-measured gives ±0.3 %. One configuration even came out 86 KB *larger* while
  compiling *less* (channels on, providers off: 33 780 112 B vs 33 694 024 B). Anything
  below ~1 % is noise, which is why the budget check has a `--tolerance` knob.
* **`providers` is a build-surface switch, not a size lever.** The five adapters share
  the HTTP/SSE plumbing that stays behind either way, so dropping Bedrock, Gemini, the
  agent CLIs, the Agents API and managed llama.cpp removes only ~2.4 KB of machine code.
  It exists so a build can refuse to *contain* code paths it will never use (AWS SigV4,
  spawning third-party agent CLIs) and so `--no-default-features` has one meaning:
  everything optional is out. Do not expect it to shrink the binary.

If you only want a smaller download, use `--profile slim` (14 %) or drop the chat
platforms (12 %); the two together give 24 %.

## How the split works

The only supported way to drop a platform family is a cargo feature, and a family may
only get one if it is *self-contained*: nothing outside `seagent-channel` names its module,
and no always-compiled module inside `seagent-channel` uses it. The rule was applied by
mapping the reference graph first:

```sh
grep -n "mod \|pub use" crates/seagent-channel/src/lib.rs
grep -rn "seagent_channel::<module>" crates/seagent-app crates/seagent crates/seagent-kernel | head -50
grep -rn "seagent_media::<module>"   crates --include=*.rs | grep -v ^crates/seagent-media
```

With a feature **off** the module is not compiled at all. `config::registry()` in
`config.rs` names every channel kind, so an off module keeps a tiny stub `build` that
returns an error instead of compiling the platform:

```text
channel kind `slack` is not compiled into this build (cargo feature `slack` is off; see docs/BUILD.md)
```

That keeps the registry table (and therefore config parsing, `seagent channel list`, the
daemon's channel startup) identical in both builds without duplicating the table.

Feature layering:

```text
crates/seagent/Cargo.toml         default   = ["channel", "providers"]
                              channel   = ["seagent-channel/all", "seagent-app/channel"]
                              providers = ["seagent-app/providers", "seagent-kernel/providers",
                                           "seagent-memory/providers", "seagent-plugin/providers",
                                           "seagent-skills/providers", "seagent-model/full"]
crates/seagent-app/Cargo.toml     default = ["channel", "providers"]   channel = ["seagent-channel/all"]
crates/seagent-kernel/Cargo.toml  default = ["providers"]              providers = ["seagent-model/full"]
crates/seagent-model/Cargo.toml   default = ["full"]                   full = [bedrock, gemini, agent-cli, agents-api, local]
crates/seagent-channel/Cargo.toml default = ["all"]                    all = [ <every platform feature> ]
```

`seagent-app` and `seagent` take `seagent-channel` with `default-features = false` (spelled as an
explicit `path` dependency — this cargo cannot override `default-features` through
`workspace = true`), so `-p seagent --no-default-features` really reaches `seagent-channel` with
no platform enabled. Verified with `cargo tree -p seagent --no-default-features -e features -i seagent-channel`
(no `seagent-channel feature "…"` lines).

The default build is unchanged: `default` → `channel` → `seagent-channel/all` → every
platform, i.e. exactly the pre-feature set of modules.

## `seagent-channel` features

One feature per self-contained platform family, all `= []` (they gate code, not
dependencies). `default = ["all"]`, `all` lists all of them.

| feature | modules it compiles |
| --- | --- |
| `slack` | `slack` (+ its `slack_actions`) |
| `mattermost` | `mattermost` |
| `email` | `email` (IMAP/SMTP) |
| `feishu` | `feishu` (also the `lark` kind) |
| `googlechat` | `googlechat` |
| `dingtalk` | `dingtalk` |
| `wecom` | `wecom` |
| `wecom_callback` | `wecom_callback` |
| `weixin` | `weixin` (also `wechat`) |
| `qqbot` | `qqbot` |
| `yuanbao` | `yuanbao` (+ `yuanbao_tools`) |
| `bluebubbles` | `bluebubbles` |
| `nextcloud_talk` | `nextcloud_talk` |
| `synology_chat` | `synology_chat` |
| `zalo` | `zalo` |
| `zalouser` | `zalouser` |
| `tlon` | `tlon` (also `urbit`) |
| `x` | `x` (also `twitter`) |
| `clickclack` | `clickclack` (+ `clickclack_discussion`) |
| `raft` | `raft` |
| `qa_channel` | `qa_channel` |
| `homeassistant` | `homeassistant` |
| `relay` | `relay` |
| `simplex` | `simplex` |
| `ntfy` | `ntfy` |
| `matrix` | `matrix`, `matrix_e2ee`, `matrix_backup`, `matrix_sas`, `matrix_trust`, `reef` |
| `matrix_backup`, `matrix_e2ee`, `matrix_sas`, `matrix_trust`, `reef` | the individual pieces (pulled in by `matrix`) |
| `nostr` | `nostr`, `buzz`, `secp256k1` |
| `buzz`, `secp256k1` | the individual pieces (pulled in by `nostr`) |
| `signal` | `signal`, `imessage`, `irc`, `twitch`, `photon` |
| `imessage`, `irc`, `twitch`, `photon` | the individual pieces (pulled in by `signal`) |

Families exist because of shared helpers found in step 1: the Signal client reuses
`sms::redact_phones_in` and `line::*`, iMessage reuses `irc::now_secs`, Twitch builds on
`irc`, Photon on `signal::http_stream`; the Matrix crypto stack (`matrix_e2ee`,
`matrix_sas`, `matrix_trust`, `matrix_backup`) shares `olm` (always compiled: the binary
uses `olm::hkdf` for its own storage) and `reef::canonical`; `buzz` (Nostr relay client)
shares `secp256k1` and `nostr`'s event types.

## `seagent-model` provider features

`seagent-model` carries one feature per optional wire-format family. Every feature is
`= []` (it gates code, not dependencies); `default = ["full"]`, and `full` lists all of
them, so a default build is the complete set. Turning one off keeps the `WireFormat`
variant and the preset table, so config parsing is identical in both builds.

| feature | modules it compiles | what you lose when it is off | size effect |
| --- | --- | --- | --- |
| `bedrock` | `bedrock`, `sigv4`, `eventstream` | AWS Bedrock Converse/ConverseStream, SigV4 signing, binary event streams | ~1–2 KB |
| `gemini` | `gemini` | the Gemini/Vertex `generateContent` adapter (the `vertex` quirk included) | <1 KB |
| `agent-cli` | `cli`, `codex_app`, `acp`, `muse` | running `claude`/`gemini`/`codex exec`, `codex app-server`, ACP agents (`copilot --acp`), Meta Muse | ~1 KB |
| `agents-api` | `agentsapi` | OpenAI Agents API (hosted agent sessions) | <1 KB |
| `local` | `local` | managed llama.cpp (`model_path` in a provider config) | <1 KB |

These are **surface** switches: measured together they remove 2 368 B.

### What cannot be gated (and why)

These stay in every build because a file outside `seagent-channel` — or an always-compiled
module inside it — names them; removing them needs edits in crates this row does not own:

| modules | blocked by |
| --- | --- |
| `discord`, `discord_voice`, `discord_transcripts` | `seagent-app/src/tui/png.rs` and `seagent/src/ops/archive.rs` call `seagent_channel::discord::zlib::inflate_raw` (zlib inflate lives in the Discord module) |
| `dave`, `mls`, `p256` | `discord_voice`/`dave` (above); `seagent/src/ops/storage.rs` uses `seagent_channel::dave::scrypt` |
| `whatsapp`, `whatsapp_cloud` | `seagent/src/telephony.rs` uses `seagent_channel::whatsapp::TelephonyTts`; `Wiring::session_origin` is typed `crate::whatsapp::SessionOrigin` in `lib.rs` |
| `msteams`, `msgraph_webhook` | `seagent/src/meetings/teams/{mod,deliver}.rs` builds `seagent_channel::msteams::Teams` and installs `msgraph_webhook` schedulers |
| `olm` | `seagent/src/ops/storage.rs` (`olm::hkdf`) and the Matrix stack |
| `sms`, `line` | shared helpers (`line::file_name`, `line::guess_mime`, `sms::redact_phones_in`) used by the always-compiled WhatsApp channel |
| `telegram`, `webhook`, `http`, `access`, `router`, `config`, `deliver`, `tool`, `message_tool`, `action_args`, `chunk`, `charset`, `markup` | core transports and the router/tool surface, named by the binary and by `pub use` in `lib.rs` |

The Discord family is the one worth revisiting: it is dead weight for a build without
Discord, but its `zlib` helper is the tree's inflate implementation. Moving `zlib` into
`seagent-channel::http` (or a small `seagent-core` helper) would let the whole
`discord + discord_voice + discord_transcripts + dave + mls + p256` block
(~700 KB of source, roughly 1 MB of the stripped binary) become one more feature.

## Per-family cost (measured 2026-11-04, round 5)

The per-family numbers below were taken on the round-5 tree; the deltas are still the
right order of magnitude, the absolute sizes have drifted a few hundred KB since.

Slim plus exactly one family, same release command line:

| build | bytes | cost of the family |
| --- | --- | --- |
| `--no-default-features` | 29 012 392 | — |
| `--no-default-features --features seagent-channel/matrix` | 29 819 136 | **+806 744** (0.77 MiB) |
| `--no-default-features --features seagent-channel/signal` | 29 429 336 | **+416 944** (0.40 MiB) |

The remaining ~3.63 MiB is the other 24 single-platform features (slack, email, feishu,
wecom*, qqbot, tlon, x, clickclack, relay, …), each a few hundred KB of HTTP/JSON client.

## Exact commands

Environment used for the 2026-11-05 measurements:

```sh
export CARGO_INCREMENTAL=0
export TMPDIR=$HOME/.cache/seagent-build/r5-d

# default: every platform and subsystem (identical behaviour to before the split)
cargo build -p seagent --release
stat -c %s target/release/seagent            # 33694024

# slim: no optional chat platform
cargo build -p seagent --release --no-default-features
stat -c %s target/release/seagent            # 29543848

# pick families explicitly
cargo build -p seagent --release --no-default-features --features seagent-channel/matrix
cargo build -p seagent --release --no-default-features --features "seagent-channel/slack,seagent-channel/ntfy"
cargo build -p seagent --release --no-default-features --features channel   # `default` = `channel`: everything
```

Checks that both halves of the split stay honest:

```sh
cargo test  -p seagent-channel --lib feature_wiring                 # 3 tests, default features
cargo test  -p seagent-channel --lib --no-default-features feature_wiring
cargo clippy -p seagent-channel --all-targets -- -D warnings
cargo check -p seagent --no-default-features
```

Note: `crates/seagent-channel/tests/*.rs` (the `real_*.rs` integration tests) use platform
modules directly and therefore need the default features; run them without
`--no-default-features`.

## Tests that keep the wiring from rotting

`crates/seagent-channel/src/lib.rs`, `mod feature_wiring`:

* `registry_lists_every_kind_once` — `config::registry()` lists every channel kind
  exactly once (no duplicate kinds after the split) and still contains the core kinds.
* `every_platform_feature_is_wired` — for every optional platform, `#[cfg(feature = …)]`
  blocks assert that the registry entry for its kind is that module's own `build` when
  the feature is on, and — when the feature is off — that the entry is the stub, whose
  error says "not compiled into this build". No builder is ever called with real
  settings, so the test is instant and does no I/O (it creates and removes one temp dir
  only in the slim configuration).

* `all_and_default_cover_every_platform_feature` — parses this crate's `Cargo.toml`
  (`include_str!`, no cargo metadata at runtime), expands `all` through the feature graph
  and asserts that `default` includes `all` and that every feature in the
  `optional_channels!` table is reachable from it (and counts the table: 39 platforms).
  Dropping one platform from `all` fails with "feature `ntfy` is not reachable from
  `all`", which is exactly the way a default build could silently lose a platform.

Adding a platform to `config.rs` without a feature, a feature without a kind, or a new
platform feature that is missing from `all`, fails one of the tests.

## `seagent-media`: no split yet (analysis, not a TODO we could not do)

The same procedure was applied to `seagent-media`. Every subsystem is reachable from an
always-compiled one, so no module qualifies:

| candidate | referenced by (always compiled) |
| --- | --- |
| `docs` (PDF/OOXML/ODF extraction) | `inbound` (`crate::docs::extract`, `wrap_external`) |
| `music_gen` | `understand` (`crate::music_gen::MusicGenerate`, `providers`) |
| `meeting` | `stt` (`crate::meeting::platforms`, `meetings`, `Meetings::refresh_transcript`) |
| `genrt`, `image_gen`, `video_gen`, `understand`, `stt`, `tts`, `voice`, `realtime`, `phone`, `audio`, `vision`, `store`, `http`, `proc`, `config`, `inbound` | named by `crates/seagent/src/**` and `crates/seagent-app/src/**` (`seagent_media::tts`, `::stt`, `::voice`, `::inbound`, `::vision`, …) |

So `cargo build -p seagent --release --no-default-features` still compiles all of
`seagent-media` (and its `image` dependency): the 4.03 MiB saved above is entirely
`seagent-channel`. A real media split needs the same two-step first: move the shared
helpers (`audio`, `proc`, `audio::*` codecs) into an ungated core, and stop `inbound`/
`understand`/`stt` from naming the optional subsystems directly (a small
`Vec<fn(&Arc<Media>) -> Vec<Arc<dyn Tool>>>` registry would do it). After that the big
subsystems — `tts` 308 KB, `image_gen` 252 KB, `stt` 216 KB, `video_gen` 208 KB,
`realtime` 200 KB, `phone` 160 KB, `meeting` 136 KB of source — become gateable.

## Size budget (checked, not remembered)

Sizes only grow if nobody watches them. Two pieces keep them honest:

| Piece | What it does |
| --- | --- |
| `tools/size-budget.tsv` | the table: build name, cargo profile, features, **budget** in bytes, last measured size, and the exact command. One line per documented build. |
| `tools/size-budget.sh` | builds every configuration in the table, compares `stat` size against the budget and exits 1 when any build is over (or missing). Builds into `${SEAGENT_SIZE_TARGET_DIR:-~/.cache/seagent-size-budget/target}`, never into `./target`, because each configuration overwrites `target/<profile>/seagent` and `target/release/seagent` is the binary the tests and e2e use. |
| `crates/seagent/tests/size_budget.rs` | the wiring test (`cargo test -p seagent --test size_budget`, no build needed): the default build must stay complete (`default` ⊇ `channel` + `providers`, `seagent-model`'s `full` must list every gated adapter), every row must name a real profile and real features, budgets must shrink in the documented order, and **every build name, measured size and budget must appear in this document**. |

```sh
tools/size-budget.sh                    # build + check every configuration (a few minutes)
tools/size-budget.sh --only slim        # one configuration
tools/size-budget.sh --json             # {"ok":true,"builds":[…]}
tools/size-budget.sh --tolerance=1      # allow 1 % (LTO layout drift)
```

Current budgets (a ceiling, not a target — a change that adds a megabyte has to be a
decision):

| build | measured | budget | headroom |
| --- | --- | --- | --- |
| default | 33694024 | 36000000 | 6.9 % |
| slim-features | 29543848 | 31000000 | 4.7 % |
| slim-profile | 28947688 | 31000000 | 6.6 % |
| slim | 25474120 | 27000000 | 5.7 % |

Budgets are deliberately ~5 % above the measured size: they should catch a feature that
adds megabytes, not punish normal code growth (which has its own review).

## Build cost

| Measurement | Value |
| --- | --- |
| clean `cargo build -p seagent --release` (one configuration, empty target dir, 20 cores) | 215 s |
| switching features and rebuilding the same target dir | 130–206 s per configuration |
| a release-only target dir | 1.3 GB |
| the full workspace `target/` with debug + `--all-targets` + test binaries | 83 GB (this audit round; it is what `cargo test --workspace` needs) |

The bulk of the build time is not `seagent` itself but the 117 dependency crates; feature
switches rebuild most of `seagent-channel`/`seagent-model` and re-run LTO on the final binary,
which is why each variant in the table costs minutes rather than seconds.

## Why not `-C link-arg=--icf=all` or `build-std`?

* `--icf=all` needs lld or gold; the workspace does not pin a linker and the default
  GNU `ld` ignores the flag (a silently ignored flag is worse than no flag).
* `build-std` is nightly-only and would make the documented `cargo build` command
  unusable for users on stable.
* `strip = "symbols"`, `lto = true`, `codegen-units = 1`, `panic = "abort"` are already
  in `[profile.release]`; `opt-level` was the one remaining free knob, which is what
  `[profile.slim]` uses.


## Caveats

* Numbers move with the tree: `cargo build -p seagent --release` re-measured a few minutes
  later on the same tree (other sessions committing) gave 33 302 568 and then
  33 304 232 bytes, i.e. the delta below is what matters, not the absolute size. Default
  and slim were measured back to back on one tree state (33 240 824 → 29 012 392).
* A slim build emits two `dead_code` warnings inside `seagent-channel`
  (`msteams::pem_to_der`, `msteams::sign_rs256`): their only in-crate callers are
  `googlechat`/`matrix`/`tlon`, which slim drops. The default build is warning-free.
* Gating is per module, not per kind: `teams`, `twilio`, `imap`, `lark`, `urbit`,
  `twitter`, `wechat`, `imsg`, `qa_channel`… aliases disappear together with their
  platform.


## Releases, installing and updating

A `v*` tag builds four tarballs with `.github/workflows/release.yml`:
`seagent-{x86_64,aarch64}-unknown-linux-{musl,gnu}.tar.gz`. The musl builds are static (they use
mimalloc instead of musl's malloc); the gnu builds need glibc 2.28 or newer. CI asserts both
(`packaging/release/check-binary.sh`) and starts every binary on AlmaLinux 8 / Alpine / native arm64.

Each tarball is a prefix: `bin/seagent`, `share/seagent/` (bundled skills, roles, plugin catalog, optional
MCPs, `vm/` image builder, `sandbox-browser/` sources, `systemd/` units), `share/doc/seagent/`.
`seagent` finds `share/seagent` at run time, in this order: `$SEAGENT_SHARE_DIR`, `<exe>/../share/seagent`,
`<exe>/../lib/seagent/share` (what `install.sh` uses for `~/.local/bin`, because `~/.local/share/seagent`
is seagent's own data dir), `/usr/local/share/seagent`, `/usr/share/seagent`, the source checkout it runs from.
`seagent doctor` reports which one it used.

* `install.sh` — `curl … | sh`; verifies `SHA256SUMS`, the Ed25519 signature when
  `SEAGENT_RELEASE_PUBKEY=release-key.pub.pem` is set, and the GitHub attestation when `gh` exists.
* `seagent update [--channel stable|lts|beta|dev] [--check] [--rollback [--restore-data]]` — downloads the
  same `seagent-<triple>.tar.gz` (musl preferred), checks `SHA256SUMS` (and `SHA256SUMS.sig` against
  `[update] verify_key` when set), swaps the binary and the bundled `share/seagent`, and backs up
  config and data first. `lts` follows `[update] lts_series = "1.4"` (or releases whose notes carry
  an `LTS` line). Installs under `/usr/bin`, `/nix/store` or with an `seagent.managed` marker refuse to
  self-update.
* Docker: `packaging/docker/README.md`. systemd: `packaging/systemd/README.md`
  (`seagent service install --system` creates the dedicated `seagent` account via sysusers.d).
* Support: `seagent doctor --bundle` writes an anonymized diagnostics archive (no upload);
  `seagent debug share` can be forbidden with `SEAGENT_DEBUG_SHARE=off`, `/etc/seagent/no-debug-upload` or the
  `government` compliance profile.
* Hygiene: `tools/secret-scan.py` (CI: working tree and full history), `cargo deny`, clippy.

### Packages, repositories, images (round 9, wave 2)

* **musl build, verified.** `rust:alpine` + `apk add build-base` + `cargo build --release --locked -p seagent`
  links a static-pie binary (36 MB, `check-binary.sh` passes; mimalloc included). Every package
  below carries that one binary.
* **deb / rpm** — `packaging/nfpm/build-packages.sh --bin <static seagent> --arch amd64|arm64 --out dist`
  (one `nfpm.yaml`; nfpm runs from the `goreleaser/nfpm` container, or a local `nfpm`). Package name
  `seagent` (replaces the pre-rename `ark-agent`).
  Layout `/usr/bin/seagent`, `/usr/share/seagent`, `/etc/seagent{,/managed.d}`, `/usr/lib/{systemd/system,sysusers.d,tmpfiles.d}`;
  `/var/lib/seagent` is created by tmpfiles/postinstall and never owned by the package. On systemd < 245
  the postinstall regenerates the unit with `seagent service print --system` (`ops/service.rs::degrade_unit`:
  < 229 moves `StartLimit*` to `[Service]`, older directives are dropped; `--systemd-version N`
  renders for another manager).
* **repositories** — `packaging/repo/make-apt-repo.py`, `make-yum-repo.sh`; `test-repos.sh` proves them
  end to end (debian:12 apt with `signed-by`, rockylinux:9 dnf with `gpgcheck`+`repo_gpgcheck`, and a
  repository signed by a foreign key is refused).
* **offline bundle** — `packaging/offline/make-offline-bundle.sh` / `install-offline.sh`.
* **distro matrix** — `python3 -I packaging/matrix/matrix.py --dist dist` (containers `seagent-test-pkg-<id>`,
  fake model from `tests/e2e/fake_provider.py`); CI job `distro-matrix` in `release.yml`.
* **images** — `Dockerfile` (debian), `Dockerfile.ubi`, `Dockerfile.distroless`; CI `images.yml`
  (native amd64/arm64, SBOM + provenance, cosign keyless). `deploy-lint.yml` lints Helm, Terraform,
  Ansible, cloud-init and the Dockerfiles.
* Enterprise docs: `docs/enterprise/`.
