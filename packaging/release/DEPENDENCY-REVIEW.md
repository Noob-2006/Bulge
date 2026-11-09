# Dependency review — how a new or updated crate gets in

`Cargo.lock` is part of the supply chain: whoever changes it changes what ships. This page is the
process a reviewer follows for any change that adds, bumps, removes or re-features a dependency,
and the budget that keeps the list from growing by accident.

Everything here is a manual review — there is no CI in this repository yet (see
[README.md](README.md#what-this-does-not-cover)). The reviewer *is* the gate.

## Who signs off

* **Author**: updates `Cargo.lock`, writes the reason comment, runs the commands below, and pastes
  the results into the PR description.
* **Reviewer**: one person with release-signing access (the release owner). Writes
  `dependency review: <github-handle>` in the PR once every item below is checked. A dependency
  change without that line is not merged, even if the code is fine.
* **Escalation**: a new `unsafe`-heavy, proc-macro or build-script crate needs two reviewers.

## The budget rule

The root `Cargo.toml` `[workspace.dependencies]` table is the *only* place a third-party crate may
be declared, and **every line carries a `#` reason**. A crate is admitted only if:

1. it removes substantially more code than it adds (a crate that saves 20 lines is not worth a
   maintainer, an advisory feed and a license to track), and
2. the reason comment says *what breaks without it*, not what it does, and
3. it is already in the tree if possible — reusing `serde`, `regex`, `ring`, `ureq` beats adding a
   second HTTP client, a second JSON parser or a second hash library.

Deviating from that (a crate used by exactly one leaf module, a transitive dependency pinned
directly to control a feature) needs a comment saying so on the same line.

## What the reviewer checks

Run from the repository root. `cargo deny` is the only external tool required
(`cargo install cargo-deny --locked`, or the distro package).

| # | Check | How |
|---|---|---|
| 1 | **Lockfile is committed and consistent** | `cargo build --workspace --locked --all-targets` — a stale `Cargo.lock` fails here, not at release time. The diff must touch `Cargo.lock` in the same commit as `Cargo.toml`. |
| 2 | **Registry + checksum pinning** | Every registry package in `Cargo.lock` has `source = "registry+https://github.com/rust-lang/crates.io-index"` and a `checksum`. `grep -c '^source = ' Cargo.lock` must equal the number of non-path packages, and no `source = "git+…"` may appear: `deny.toml` sets `unknown-git = "deny"`, `unknown-registry = "deny"`. |
| 3 | **Advisories / licenses / bans / sources** | `cargo deny check` — must be clean. Licenses must be in the allowlist in `deny.toml`; adding a license is a legal decision, not a merge detail. `yanked = "deny"`. |
| 4 | **Feature audit** | Default features off unless justified: `default-features = false` plus an explicit `features = [...]`. Check what a new feature drags in with `cargo tree -e features -i <crate>` and `cargo tree -p <crate> --edges normal,build`. A "convenience" feature that pulls a TLS stack or an async runtime is a rejection. |
| 5 | **Build script / proc-macro / `unsafe` scrutiny** | `cargo tree -p <crate> --edges build` and `ls ~/.cargo/registry/src/*/<crate>-<ver>/build.rs` — a `build.rs` runs arbitrary code on every developer and release machine; a proc-macro runs inside `rustc`. Read it. Then look for `unsafe`: `grep -rn 'unsafe' ~/.cargo/registry/src/*/<crate>-<ver>/src | wc -l`, and read every hit. `#![forbid(unsafe_code)]` at the top is the answer you want. |
| 6 | **Duplicate versions** | `cargo tree --duplicates` and `cargo deny check bans`. `multiple-versions = "warn"` in `deny.toml`; every *new* duplicate needs a sentence in the PR saying why it cannot be deduped. |
| 7 | **Typosquat / provenance** | The crate must exist on crates.io with a repository link that points at the upstream project, and be published by the same owner as the previous version. Diff the crate name against the one you meant (`serde_jsno` vs `serde_json`), check the download count is not single digits, and prefer the crate the upstream project itself links to. |
| 8 | **Cost** | Binary size and build time are tracked in [docs/BUILD.md](../../docs/BUILD.md). Compare `stat -c %s target/release/seagent` before/after; a dependency that adds >1 % to the release binary needs a note. |
| 9 | **Release artifacts follow** | The SBOM is generated from `Cargo.lock`, so any change here changes `sbom.spdx.json`; the next release regenerates it (see [README.md](README.md)). Nothing to do in the PR beyond leaving the lockfile consistent. |

## Security advisories (OSV)

`seagent` ships its own OSV check: `seagent security audit --supply-chain` feeds every `Cargo.lock` entry
to OSV and reports findings by severity (`--fail-on high` for gating, `--format json` for tooling).
It is the same data `cargo deny check advisories` uses (`RUSTSEC` is mirrored into OSV), so either
command is an acceptable source; run both if you have cargo-deny installed.

Triage a finding like this, and record the outcome in the PR that fixes or accepts it:

1. **Is it reachable?** Which crate/feature activates the dependency, and does `seagent` use the
   affected API? `cargo tree -i <crate>` answers the first half; read the advisory for the second.
   An advisory in a build-only or unused-feature dependency is still fixed, just not urgently.
2. **Severity + exploitability**: prefer the upstream advisory's CVSS and its "affected functions"
   list over the coarse OSV severity. Memory-safety issues in parsers that read untrusted input
   (network, model output, plugin code) are treated as exploitable by default.
3. **Fix**: upgrade (`cargo update -p <crate>`), or pin a patched version, or drop the feature that
   pulls the vulnerable code. Vendoring a patch is a last resort and needs a comment in
   `Cargo.toml` with the upstream PR link.
4. **Accept**: only when the code path is provably unreachable. Write the reason, the advisory id,
   and an expiry date in the PR; re-check at the next monthly pass.
5. **Time limits**: reachable critical/high → patch within 7 days (out-of-band release if needed);
   medium → 30 days; low/unreachable → next scheduled update.

## Cadence

* **Weekly**: `seagent security audit --supply-chain` (or `cargo deny check advisories`) on `main`.
* **Monthly**: `cargo update --dry-run` review, pick the patch/minor bumps, run the full test suite
  and regenerate the SBOM. Group bumps into one PR so the review effort is amortised.
* **Every release**: `cargo deny check` is part of the release checklist; a release is not cut on a
  tree with a known reachable advisory.
* **Major versions** (tokio-sized or a `0.x` minor with breaking changes of a core crate): their own
  PR, never bundled with feature work.

## PR checklist (copy into the description)

```
- [ ] reason comment added/updated in Cargo.toml [workspace.dependencies]
- [ ] Cargo.lock committed, `cargo build --workspace --locked --all-targets` passes
- [ ] `cargo deny check` clean (advisories, licenses, bans, sources)
- [ ] features audited (`default-features = false` unless justified)
- [ ] build.rs / proc-macro / unsafe read (or: none present)
- [ ] no new duplicate versions (or explained)
- [ ] crates.io provenance + typosquat check done
- [ ] `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] release binary size delta noted
```

## Current direct-dependency budget

Derived from the `#` comments in the root `Cargo.toml` (`[workspace.dependencies]`). Path
dependencies inside the workspace (`seagent-core`, `seagent-kernel`, …) are not budgeted: they are this
repository and are reviewed as code.

| Crate | Version | Why it is here (from `Cargo.toml`) |
|---|---|---|
| `serde` | 1 | Serialization of every event / protocol type (`derive` feature) |
| `serde_json` | 1 | JSON-RPC, JSONL log, provider wire formats |
| `toml` | 0.9 | Human-editable config (`parse`, `display`, `serde`, no default features) |
| `ureq` | 3 | Blocking HTTP + TLS with the smallest dependency tree (`rustls` feature) |
| `regex` | 1 | `grep` tool and secret-pattern matching |
| `libc` | 0.2 | Process groups / signals for the shell tool |
| `rustls` | 0.23 | Already pulled in by `ureq`; used directly by `seagent-net` for WebSocket, webhook signatures, OAuth PKCE |
| `webpki-roots` | 1 | Trust anchors for `rustls` — *no reason comment in `Cargo.toml` yet* (see gaps) |
| `ring` | 0.17 | Ed25519/HMAC primitives for signing and secret sealing — *no reason comment yet* |
| `base64` | 0.23 | Encoding for tokens, signatures and attachments — *no reason comment yet* |

| `wasmi` | 2 | iOS shell substitute: the `wasm` exec backend runs WASI tools in this WebAssembly *interpreter* (see below). Optional; not in the default build |

### `wasmi` (iOS only, review notes)

* **Why**: iOS forbids `fork`/`exec`, JIT and hypervisors, so commands cannot run as processes, in
  a microVM or under a JIT runtime (wasmtime, V8). An interpreter running code inside the app's
  sandbox is the accepted pattern. `wasmi` is the pure-Rust, non-JIT, `no_std`-capable
  interpreter used by Parity/Substrate; it is what `exec.backend = "wasm"`
  (`crates/seagent-tools/src/exec/wasm/`) runs `wasm32-wasip1` tools with. WASI preview 1 itself
  is implemented in that module (≈900 lines, no `wasmi_wasi` / `wasi-common` / `cap-std` tree).
* **Where it is linked**: `seagent-tools` declares it as a target dependency for
  `cfg(target_os = "ios")` and as an optional dependency behind the `wasm` feature (`seagent`'s
  `wasm` feature forwards it). The default Linux/macOS/Windows/Android binaries do not contain it
  (`cargo tree -p seagent -e normal -i wasmi` is empty for them).
* **Features**: `default-features = false`, `std` + `validate` (every module is validated before
  it is translated) + `auto-dispatch` (tail-call dispatch only when the build guarantees sibling
  calls; a debug build overflows the stack without it) + `simd` (uutils coreutils' WASI build
  contains simd128 paths). No `wat` text parser, no `memory64`.
* **Tree**: `wasmi` 2.0.0, `wasmi_core`, `wasmi_ir`, `wasmi_collections` (same project and owner),
  `wasmparser` 0.228 (Bytecode Alliance), `spin` 0.9 (no-std locks). Licenses MIT / Apache-2.0
  (`wasmparser`: Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT). No C code.
* **Build scripts**: `wasmi` and `wasmi_ir` emit `cfg`s from `OPT_LEVEL` / target arch / target
  features only (read: no file system, network or tool invocation); `wasmparser`'s sets a cfg.
* **`unsafe`**: ≈300 sites in `wasmi` (the register-machine executor and linear-memory access),
  ≈140 in `spin`. That is the interpreter's job; the agent never hands it a pointer, and the guest
  can only reach the host through the WASI functions in `exec/wasm/wasi.rs`, which bounds-check
  every guest buffer and confine every path. Fuel metering (resumable on exhaustion) gives the
  kill/timeout path; `StoreLimits` caps linear memory.
* **Payload**: the iOS app bundles WASI *modules* as data (uutils coreutils 0.12.0, built from
  crates.io with `--locked` by `apps/desktop/scripts/build-wasi-tools.sh`; each module's SHA-256
  is pinned in `tools.json` and the backend refuses a mismatch). They are code for the
  interpreter, never for the CPU, and are reviewed like any other bundled tool set.

**Gaps (reviewer action, not yet fixed):** `webpki-roots`, `ring` and `base64` are declared without
a reason comment, which the budget rule above requires. They are load-bearing (TLS trust, crypto,
wire encoding), so the fix is to add the comment, not to remove the crate.

## App shell budget (`apps/desktop`, separate)

The GUI app (Tauri 2: window, tray, installers, mobile targets) is a **separate Cargo workspace**
with its own `apps/desktop/Cargo.lock`. It is *not* a member of the root workspace, so nothing
above applies to it automatically and nothing in it reaches the agent: `cargo deny check`,
`seagent security audit --supply-chain` and the SBOM at the repository root cover the agent only,
and the agent binary that ships inside the app is byte-for-byte the one the root workspace builds.

Why a separate budget: Tauri brings tokio, wry/tao, the WebView bindings (WebView2, WebKitGTK,
WKWebView, Android WebView) and their build scripts — hundreds of crates that the headless agent
must never depend on. Keeping them in their own lockfile keeps the agent's tree, review effort and
attack surface unchanged.

Rules for `apps/desktop`:

* Same review process (who signs off, the checklist) applied to `apps/desktop/Cargo.lock`, run from
  `apps/desktop`: `cargo deny check` (with the root `deny.toml`: `cargo deny --manifest-path
  apps/desktop/Cargo.toml check --config deny.toml`), `cargo tree --duplicates`.
* Direct dependencies are listed with a `#` reason in `apps/desktop/src-tauri/Cargo.toml` and
  `plugins/seagent-mobile/Cargo.toml`: `tauri` and official `tauri-plugin-*` crates (single
  instance, autostart, updater, dialog, opener, barcode scanner), `serde`/`serde_json`, `base64`,
  `tokio` (already in Tauri's tree), `rustls` + `tokio-rustls` + `ring` (pinned TLS to a paired
  host — `ring` provider, no `aws-lc`/cmake for mobile cross builds), `sys-locale`.
  Anything else follows the budget rule above.
* An advisory in the app's tree is triaged like one in the agent's, but ships through an app
  release (the in-app updater), not an agent release.
* Non-crate payload: the Linux **AppImage** bundles one font, Noto Sans TC (variable TTF, Noto CJK
  2.004, SIL OFL 1.1, from googlefonts/noto-cjk at a pinned commit, SHA-256 checked by
  `apps/desktop/scripts/fetch-cjk-font.sh`; `OFL.txt` shipped next to it, entry in
  `THIRD_PARTY_NOTICES.md`). Reason: an AppImage cannot pull a distro font package and the UI is
  mostly Chinese. It is data (no code), used only when the system has no CJK font. Bumping it means
  changing the commit and hash in that script, nothing else.
