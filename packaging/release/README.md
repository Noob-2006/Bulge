# Release packaging — checklist and tooling

Everything in this directory is release plumbing for the `ark` binary. It is **manual by design**:
there is no CI pipeline in this repository (see [What this does not cover](#what-this-does-not-cover)),
so the checklist below *is* the release process.

| File | What it does |
|---|---|
| `sbom.py` | Builds (and `--check`s) an SPDX 2.3 JSON SBOM from `Cargo.lock` + `cargo metadata`. Stdlib only, offline, byte-deterministic. |
| `gen-key.sh` | Creates the Ed25519 release keypair with `openssl` (private key 0600). Run once, offline. |
| `sign.sh` | Detached base64 Ed25519 signature over `SHA256SUMS`; refuses group/world-readable keys. |
| `verify-release.sh` | Verifies a downloaded dist directory: signature → per-file hashes → no extra files → SBOM parses. |
| `repro-check.sh` | Builds the tree twice from different paths and compares artifact hashes. |
| `DEPENDENCY-REVIEW.md` | The process for adding/bumping a crate, the dependency budget, advisory triage. |

Requirements: `bash`, `openssl` 3.x, `sha256sum` (coreutils or `shasum`), `tar`, `cargo`, `python3`
(3.8+). Nothing else; no network for any of the verify/check steps.

## One-time: create the signing key

Do this offline, on the machine that will cut releases, and store the private key **outside** the
repository:

```sh
packaging/release/gen-key.sh --out-dir ~/ark-release-keys
# ~/ark-release-keys/release-key.pem      0600   <- never commit, upload or copy to CI
# ~/ark-release-keys/release-key.pub.pem  0644   <- published with every release
```

Back the private key up (offline medium or password manager). Losing it means re-issuing the key
and re-signing future releases; leaking it means every past signature becomes worthless. A
compromised key is rotated by publishing `release-key-<year>.pub.pem` and announcing it — there is
no revocation or timestamping infrastructure here, so old releases have to be re-verified against
the key that was current when they were built.

## Release checklist

Run from the repository root. `VERSION` is the number in `[workspace.package]` of `Cargo.toml`.

**0. Preconditions**
- [ ] `git status` clean; `Cargo.lock` committed.
- [ ] Every dependency change went through [DEPENDENCY-REVIEW.md](DEPENDENCY-REVIEW.md) (reviewer
      line in the PR).
- [ ] No known reachable advisory: `ark security audit --supply-chain --fail-on high`
      (or `cargo deny check advisories`).

**1. Version bump**
- [ ] `Cargo.toml` → `[workspace.package] version = "$VERSION"`.
- [ ] `cargo build --workspace` once so `Cargo.lock` records the new workspace versions, then
      confirm the lockfile diff only touches the workspace crates.

**2. Gate — do not build a release from a tree that does not pass**
- [ ] `cargo build --workspace --all-targets`
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo deny check`

**3. Build the dist directory**

```sh
TAG_EPOCH=$(git log -1 --format=%ct)          # release time = commit time, not now
rm -rf dist && mkdir -p dist
export SOURCE_DATE_EPOCH=$TAG_EPOCH
cargo build -p ark --release
cp target/release/ark                     dist/
cp README.md THIRD_PARTY_NOTICES.md       dist/
cp ~/ark-release-keys/release-key.pub.pem dist/
```

**4. SBOM**

```sh
packaging/release/sbom.py --out dist/sbom.spdx.json
packaging/release/sbom.py --check --out dist/sbom.spdx.json   # fails on a malformed document
```

`SOURCE_DATE_EPOCH` also fixes `creationInfo.created`, so the SBOM is identical for a rebuild of
the same tag. Do not regenerate it with a different epoch — that is how two "identical" releases
start differing.

**5. Checksums**

```sh
( cd dist && LC_ALL=C sha256sum * | sort -k2 > SHA256SUMS )
```

Generate this *after* every other file is in place, and check the list covers them:
`wc -l dist/SHA256SUMS` should equal `ls dist | wc -l` minus `SHA256SUMS` (the file cannot hash
itself, and `verify-release.sh` knows that).

**6. Sign**

```sh
packaging/release/sign.sh dist/SHA256SUMS ~/ark-release-keys/release-key.pem
# -> dist/SHA256SUMS.sig  (base64, 64 bytes of Ed25519, self-verified before it is written)
```

**7. Reproducible-build check**

```sh
packaging/release/repro-check.sh            # quick: the `ark` binary, ~1-2 minutes
packaging/release/repro-check.sh --full     # whole workspace + every .rlib, several minutes
```

Exit 0 = every artifact hash matched across the two build paths. Exit 1 = a DIFF table; the
release is blocked until the cause is understood. **Current expected result:** the `ark` binary
reports DIFF because several crates embed `env!("CARGO_MANIFEST_DIR")` (`ark-kernel/selfrepo.rs`,
`ark-browser`, `ark-skills`, `ark-vm`, `ark-plugin`), which bakes the build directory into the
binary. The script prints the grep to find them; making those paths relative is the fix, and until
it lands the exception must be recorded in the release notes.

**8. Verify what you are about to publish**

```sh
packaging/release/verify-release.sh dist --key ~/ark-release-keys/release-key.pub.pem
```

This runs exactly the checks a downloader runs: signature over `SHA256SUMS`, every listed file,
no unlisted files, SBOM parses. If it fails, go back to step 3 — do not publish a hand-patched
directory.

**9. Publish** (release page / mirror), all from `dist/`:
`ark`, `README.md`, `THIRD_PARTY_NOTICES.md`, `sbom.spdx.json`, `SHA256SUMS`, `SHA256SUMS.sig`,
`release-key.pub.pem`.

**10. After the release**
- [ ] Tag pushed: `git tag -s v$VERSION -m "ark $VERSION" && git push origin v$VERSION`.
- [ ] Release notes state the SBOM file name and the repro-check result (including any accepted
      exception from step 7).
- [ ] Archive the `dist/` directory and its `SHA256SUMS.sig` — the signature cannot be
      regenerated if the key is rotated.

## Verifying a download (what a user runs)

```sh
tar xf ark-$VERSION.tar.gz && cd ark-$VERSION
packaging/release/verify-release.sh . --key release-key.pub.pem   # or verify-release.sh alone
```

It needs only `bash`, `openssl`, `sha256sum` and `python3`. If the downloaded tarball does not
include `packaging/release/`, copy `verify-release.sh` and `sbom.py` next to it. Passing `--key`
with a key obtained
independently (website, git history) is what protects against a swapped key; the default
`--key <dir>/release-key.pub.pem` only protects against corruption and says so in its output.

## What this does not cover

- **No CI.** Every step above is manual and trusted to the operator. Nothing prevents a release
  that skipped step 2 or 7 except the checklist itself.
- **Key custody is the operator's job.** `gen-key.sh` creates the key; protecting it, backing it
  up, and rotating it are not automated. There is no HSM, no key split, no timestamping/notary —
  a signature proves *who signed* at some point, not *when*.
- **Rust crates only.** The SBOM describes `Cargo.lock`. The browser extension (`ui/`), the
  sandbox image and any JS/npm tooling are not in it.
- **One platform, one artifact.** Only the host `ark` binary is covered. Container images
  (`packaging/sandbox-browser`), the VM image (`packaging/vm`) and the systemd units are built
  elsewhere and are not signed here.
- **Not a vulnerability scanner.** The check in step 0 is advisory data (OSV/RUSTSEC) at the
  moment of the release; it says nothing about the day after.
