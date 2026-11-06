# Contributing to SE Agent

> 中文摘要：歡迎貢獻。送出前請跑過 `cargo clippy` 與測試；每個 commit 都要加 `Signed-off-by`（`git commit -s`），代表你有權以 MIT 授權提交這段程式碼。安全漏洞請走 [SECURITY.md](SECURITY.md) 的私下管道，不要開公開 issue。

Thank you for helping. This guide covers how to build, test and submit changes.

## Before you start

- **Bugs**: open an issue with `seagent --version`, `seagent doctor` output (redacted), what you
  did, what you expected and what happened. See [docs/install.md §9.8](docs/install.md#98-還是不行).
- **Security problems**: never in a public issue. Follow [SECURITY.md](SECURITY.md).
- **Larger changes** (new tools, channels, protocol or config changes): open an issue first so the
  design can be agreed before you write the code.
- Be kind: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies everywhere in the project.

## Build and test

Requirements: Rust 1.80 or later, Python 3 (end-to-end tests), git. Optional: podman or docker
(container tests and the distro install matrix), QEMU with `/dev/kvm` (VM tests).

```bash
cargo build -p seagent                                  # debug build
cargo clippy --workspace --all-targets -- -D warnings   # must be clean
cargo test --workspace                                  # unit and integration tests
cargo build --release -p seagent
python3 -I tests/e2e/run.py target/release/seagent      # end-to-end, against a fake model
```

Tests never use a real model, a real account or your real home directory:

- Point everything at a throwaway home: `SEAGENT_HOME=$(mktemp -d)`. The test suite enforces this
  (`crates/seagent/tests/test_hygiene.rs`): tests use self-cleaning temp dirs, never read the real
  `$HOME`, and never signal processes they did not start.
- Tests that need the network, containers or upstream checkouts are `#[ignore]` or skip themselves
  when the prerequisite is missing; say in the PR which of them you ran.
- Packaging changes: build the packages (`packaging/nfpm/build-packages.sh`) and run the distro
  matrix for the affected families (`packaging/matrix/matrix.py --only …`).

## Making a change

- Match the surrounding code: its naming, comment density and idioms. Explain *why* in comments,
  not what the next line does.
- Add a test for every bug fix (it should fail before the fix) and for every new behaviour.
- Update the documentation the change affects (`docs/`, `--help` text, config defaults).
- No hardcoded user paths, hosts or credentials; secrets come from the vault
  (`{{secret:NAME}}`), never from config files or source.
- Keep commits focused. Write the subject in the imperative ("Fix …", "Add …") and explain the
  reason in the body.

## Developer Certificate of Origin

Every commit must be signed off, certifying the [Developer Certificate of Origin
1.1](https://developercertificate.org/): you wrote the change, or otherwise have the right to submit
it under the project's license (MIT).

```bash
git commit -s        # adds "Signed-off-by: Your Name <you@example.com>"
```

Use your real name or a name you are publicly known by. Commits without a sign-off cannot be
merged.

Code ported from another project must be under a license compatible with MIT, and the port must
be recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (and in `REUSE.toml` when the
license is not MIT).

## Pull requests

A pull request is ready for review when:

- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes, and you ran the end-to-end suite if the change touches the
      CLI, daemon, console or protocols
- [ ] new behaviour has tests and documentation
- [ ] every commit is signed off
- [ ] the description says what changed, why, and how you tested it

AI-assisted contributions are welcome; you are responsible for them like for any other code:
review, test and understand everything you submit.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
