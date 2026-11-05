# Ansible role `seagent`

Installs SE Agent (signed apt/yum repository, a package file, or the static tarball), applies the
organisation policy to `/etc/seagent/managed.toml`, runs the unattended `seagent setup` (flags and
`SEAGENT_SETUP_*` of `crates/seagent/src/setup_server.rs`) as the `seagent` account and enables the `seagentd`
system service. Idempotent: a second run changes nothing.

Variables and defaults: `defaults/main.yml`. Examples: `examples/site.yml` (repository),
`examples/airgapped.yml` (offline bundle). The API key is passed in the environment of the one
`seagent setup` task (`no_log: true`) and lands in seagent's vault, not in any file the role writes.

Check without a host: `ansible-playbook --syntax-check -i localhost, examples/site.yml`
(CI: `.github/workflows/deploy-lint.yml`).
