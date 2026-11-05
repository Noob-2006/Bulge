# Ansible role `ark`

Installs ark (signed apt/yum repository, a package file, or the static tarball), applies the
organisation policy to `/etc/ark/managed.toml`, runs the unattended `ark setup` (flags and
`ARK_SETUP_*` of `crates/ark/src/setup_server.rs`) as the `ark` account and enables the `arkd`
system service. Idempotent: a second run changes nothing.

Variables and defaults: `defaults/main.yml`. Examples: `examples/site.yml` (repository),
`examples/airgapped.yml` (offline bundle). The API key is passed in the environment of the one
`ark setup` task (`no_log: true`) and lands in ark's vault, not in any file the role writes.

Check without a host: `ansible-playbook --syntax-check -i localhost, examples/site.yml`
(CI: `.github/workflows/deploy-lint.yml`).
