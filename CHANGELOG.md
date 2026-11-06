# Changelog

All notable changes to SE Agent are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked **Security**.

## [Unreleased] — 0.1.0

First public release candidate.

### Added
- Agent kernel: one-shot runs, interactive chat, background daemon (`seagentd`), sessions with
  branching and search, cron schedules, long-running goals, heartbeat, sub-agent fleet.
- Two gates (privilege, data egress) and a four-tier risk model with task envelopes, scoped and
  time-limited grants, hard limits that cannot be disabled, dual-control approvals.
- Isolation: microVMs (Firecracker / QEMU), gVisor, containers, bwrap / Landlock; a graphical
  desktop VM driven by computer use, with the agent's browser running inside it and human
  takeover from the web console.
- Web console for operations: devices, agents, approvals, audit (CSV / HTML export), workspace
  pane with live browser and desktop views.
- 46 chat channels, MCP client and server, ACP, A2A, OpenAI-compatible API, nodes.
- Enterprise: OIDC / SAML login, roles, managed policy files, audit forwarding, change-control
  integration, offline install bundle.
- Packages: one-command installer, deb, rpm, pacman (AUR `seagent-bin`), apk (OpenRC), npm
  wrapper, Nix flake, containers, Helm, Ansible.
- Documentation: install guide with troubleshooting, FAQ, security policy, contribution guide.

### Changed
- The project was renamed from `ark` to SE Agent (`seagent`). `ARK_*` variables, per-user `ark`
  directories, project `.ark/` directories and vault keys stored under the old names keep
  working; the `seagent` package replaces `ark-agent`.

### Security
- A human takeover now stops every browser tool, not only those on the bot desktop.
- Session names longer than 48 characters can no longer map two sessions to one sandbox.
- API keys with control or non-ASCII characters (for example a terminal paste escape) are
  rejected when stored instead of being sent in request headers.
