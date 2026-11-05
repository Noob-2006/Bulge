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
| 8 | **Cost** | Binary size and build time are tracked in [docs/BUILD.md](../../docs/BUILD.md). Compare `stat -c %s target/release/ark` before/after; a dependency that adds >1 % to the release binary needs a note. |
| 9 | **Release artifacts follow** | The SBOM is generated from `Cargo.lock`, so any change here changes `sbom.spdx.json`; the next release regenerates it (see [README.md](README.md)). Nothing to do in the PR beyond leaving the lockfile consistent. |

## Security advisories (OSV)

`ark` ships its own OSV check: `ark security audit --supply-chain` feeds every `Cargo.lock` entry
to OSV and reports findings by severity (`--fail-on high` for gating, `--format json` for tooling).
It is the same data `cargo deny check advisories` uses (`RUSTSEC` is mirrored into OSV), so either
command is an acceptable source; run both if you have cargo-deny installed.

Triage a finding like this, and record the outcome in the PR that fixes or accepts it:

1. **Is it reachable?** Which crate/feature activates the dependency, and does `ark` use the
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

* **Weekly**: `ark security audit --supply-chain` (or `cargo deny check advisories`) on `main`.
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
dependencies inside the workspace (`ark-core`, `ark-kernel`, …) are not budgeted: they are this
repository and are reviewed as code.

| Crate | Version | Why it is here (from `Cargo.toml`) |
|---|---|---|
| `serde` | 1 | Serialization of every event / protocol type (`derive` feature) |
| `serde_json` | 1 | JSON-RPC, JSONL log, provider wire formats |
| `toml` | 0.9 | Human-editable config (`parse`, `display`, `serde`, no default features) |
| `ureq` | 3 | Blocking HTTP + TLS with the smallest dependency tree (`rustls` feature) |
| `regex` | 1 | `grep` tool and secret-pattern matching |
| `libc` | 0.2 | Process groups / signals for the shell tool |
| `rustls` | 0.23 | Already pulled in by `ureq`; used directly by `ark-net` for WebSocket, webhook signatures, OAuth PKCE |
| `webpki-roots` | 1 | Trust anchors for `rustls` — *no reason comment in `Cargo.toml` yet* (see gaps) |
| `ring` | 0.17 | Ed25519/HMAC primitives for signing and secret sealing — *no reason comment yet* |
| `base64` | 0.23 | Encoding for tokens, signatures and attachments — *no reason comment yet* |

**Gaps (reviewer action, not yet fixed):** `webpki-roots`, `ring` and `base64` are declared without
a reason comment, which the budget rule above requires. They are load-bearing (TLS trust, crypto,
wire encoding), so the fix is to add the comment, not to remove the crate.
