# Security policy

> 中文摘要：發現安全漏洞請**私下**回報（GitHub 的「Report a vulnerability」），不要開公開 issue。我們會在 7 天內回覆，修好後再公開。實作細節見 [docs/SECURITY.md](docs/SECURITY.md)。

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue, discussion or pull request.

- Use GitHub's private vulnerability reporting: the repository's **Security** tab →
  **Report a vulnerability**.
- Include what you found, how to reproduce it (commands, configuration, the version from
  `seagent --version`), and the impact you expect.
- Do not include real secrets, tokens or personal data. Redacted output from `seagent doctor`
  and the logs is enough.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement of your report | within 7 days |
| First assessment (accepted / needs more information / not a vulnerability) | within 14 days |
| Fix or mitigation for an accepted report | as soon as practical; we keep you informed |
| Public disclosure | after a fix is released, or 90 days after the report, whichever comes first, coordinated with you |

We credit reporters in the release notes unless you ask us not to.

## Supported versions

SE Agent is pre-1.0. Security fixes go into the latest release only; upgrade to receive them
(`seagent update`, or your package manager).

| Version | Supported |
|---|---|
| latest 0.x release | yes |
| older releases | no |

## Scope

In scope: the `seagent` binary and daemon, the web console and its APIs, the install scripts and
packages built from this repository, and the bundled skills and plugins.

Especially interesting: anything that lets an agent bypass the risk gates, the hard limits or a
human takeover; secret leakage from the vault, logs or exports; sandbox or VM escapes;
authentication or authorization flaws in the console, ARP or the OpenAI-compatible API.

Out of scope: vulnerabilities in third-party model providers, chat platforms or upstream
projects (report those to them); findings that need an already-compromised host or a malicious
local administrator; denial of service by exhausting your own model budget.

## Safe harbor

We will not pursue legal action against good-faith research that follows this policy: test only
against your own installations, do not access other people's data, and give us reasonable time
to fix the problem before disclosure.

## How SE Agent is secured

The implementation of the vault, risk gates, sandboxing, audit log and release signing is
documented in [docs/SECURITY.md](docs/SECURITY.md); releases are verifiable as described in
[docs/install.md](docs/install.md#5-驗證你下載的檔案).
