# Enterprise network, isolation and secrets

What ark does in a corporate network, on old kernels, and with an enterprise secret manager.
Every setting below is shown by `ark doctor`; isolation is shown by `ark sandbox explain`.

## Network (`[network]`)

One client builder (`ark_net::http::builder`) creates every outbound HTTP client — model
providers, channels, web tools, A2A, MCP, telemetry, update, skills hub — and the raw TLS
streams (WebSocket gateways, IRC, SMTP/IMAP) use the same roots and proxy. A lint test
(`crates/ark/tests/http_client_lint.rs`) fails the build when code creates a client elsewhere.

```toml
[network]
proxy = "http://proxy.corp:3128"          # else $HTTPS_PROXY / $HTTP_PROXY / $ALL_PROXY
no_proxy = ["10.0.0.0/8", "*.corp.example", "vault.corp:8200"]   # + $NO_PROXY
ca_file = "/etc/pki/tls/certs/corp-bundle.pem"  # replaces the bundled roots; else $ARK_CA_BUNDLE / $SSL_CERT_FILE / …
client_cert = "/etc/ark/tls/svid.pem"     # optional client certificate for every outbound TLS
client_key = "/etc/ark/tls/svid.key"
offline = false                           # see below
offline_allow = ["llm-gateway.corp"]      # still reachable when offline
```

NO_PROXY understands exact hosts, `.suffix`, `*.suffix`, IPs, CIDR ranges, `host:port` and `*`.
Loopback always goes direct. Raw TLS streams tunnel through an `http://` proxy with `CONNECT`.

### Fully offline

`[network] offline = true` (or `ARK_NETWORK_OFFLINE=1`) is one switch: no update check, no
models.dev price refresh, no skills hub, no telemetry export, and the web tools are not offered
to the model. As a second line, every client refuses public hosts; loopback, private ranges,
`*.localhost`, the NO_PROXY hosts and `offline_allow` stay reachable (an air-gapped LAN model or
an on-prem Vault). `ARK_OFFLINE=1` keeps its older, narrower meaning: no automatic background
downloads (the test suite runs under it).

## Native TLS and mutual TLS for the app server

```toml
[app.exposure]
tls = true
cert = "/etc/ark/tls/server.pem"
key = "/etc/ark/tls/server.key"
client_auth = "require"                   # off | optional | require
client_ca = "/etc/ark/tls/clients-ca.pem"
client_identities = [ { id = "spiffe://corp.example/ops/*", scope = "operator" } ]
node_identities = [ "spiffe://corp.example/ark/node/*" ]
```

Required mTLS counts as device-bound authentication for the public-exposure check (A9). A
verified client certificate maps to a token scope or RBAC role through `client_identities`
(SPIFFE ID, other SAN URI, `dns:<name>` or `sha256:<fingerprint>`; a trailing `*` is a prefix).

### Workload identity for nodes

With `node_identities`, a node presenting an allowed SPIFFE X.509-SVID pairs itself (no pairing
code) and is bound to that identity; from then on the SVID replaces its device token, and no
other identity or token can take the node over. Cloud IAM identities that federate to X.509
(SPIRE node attestors for AWS/GCP/Azure, IAM Roles Anywhere) use the same path.

## Isolation on old kernels

`[exec] backend = "auto"` prefers a microVM, then steps down — and says why at each step:

| host | result |
|---|---|
| bwrap + user namespaces | bwrap (namespaces, seccomp deny-list, home hidden) |
| no user namespaces (RHEL 7/8 default) | Landlock if the kernel has it, else docker, else host + static gates |
| kernel < 5.13 (AL2 4.14, RHEL 8 4.18) | no Landlock: bwrap, docker or rootless podman (needs user namespaces) |
| Landlock ABI < 4 (kernel < 6.7) | Landlock restricts files only; a network-less sandbox needs bwrap or a container |

bwrap runs with a seccomp deny-list (`[exec.bwrap] seccomp = true`): keyrings, mounts and new
namespaces, kexec/modules, bpf, perf, userfaultfd, handle-based opens, `ptrace`.

`[exec.cgroups] enabled = true` gives every command its own cgroup (v1 or v2) when ark runs in
a delegated subtree (the shipped systemd units set `Delegate=yes`): `memory_mb` and `pids_max`
caps apply, and the reaper also kills processes that escaped their process group.

## Secret sources

`<config>/secret_sources.toml`, managed with `ark secrets <source> setup|set|remove|status|sync`.
All of them pull values into the environment at process start (cached, never blocking start-up).

| source | how | auth |
|---|---|---|
| `vault` | HashiCorp Vault KV v2 over HTTP (full implementation) | `$VAULT_TOKEN` or AppRole (`role_id` + `$VAULT_SECRET_ID`), Enterprise namespaces |
| `aws` | `aws secretsmanager get-secret-value` | the CLI's own (instance role, SSO, web identity) |
| `gcp` | `gcloud secrets versions access` | the CLI's own (workload identity, ADC) |
| `azure` | `az keyvault secret show` | the CLI's own (managed identity, `az login`) |
| `bitwarden`, `onepassword`, `command` | as before | |

```toml
[vault]
enabled = true
addr = "https://vault.corp:8200"
mount = "secret"
auth = "approle"
role_id = "8f0c…"
env = { OPENAI_API_KEY = "ark/providers#openai", OPENAI_API_KEY__ENG = "ark/teams/eng#openai" }

[aws]
enabled = true
region = "eu-west-1"
env = { ANTHROPIC_API_KEY = "prod/ark#anthropic" }   # `#key` picks a field of a JSON secret

[gcp]
enabled = true
project = "corp-ai"
env = { GEMINI_API_KEY = "gemini-key@latest" }

[azure]
enabled = true
vault_name = "corp-kv"
env = { AZURE_OPENAI_API_KEY = "azure-openai-key" }
```

Vault traffic follows `[network]` (proxy, internal CA).

## Key rotation

* `ark secrets rekey [--new-backend passphrase|env|keyring|tpm]` — re-encrypt the local vault
  under a new key: `ARK_VAULT_NEW_PASSPHRASE_FILE` / `ARK_VAULT_NEW_PASSPHRASE` /
  `ARK_VAULT_NEW_KEY`; the old key comes from the usual `ARK_VAULT_*`. A failure restores the
  previous file.
* `ark secrets rotate NAME --value-stdin | --generate | --rotate-command CMD` — store a new
  value; when the `vault` source binds NAME, a new KV version is written to Vault (other fields
  of the secret are kept), so every host picks it up.
* `ark secrets rotation set NAME --every-days 30 --rotate-command "/usr/local/bin/new-openai-key"`
  and `ark secrets rotation run` (from cron or a systemd timer) — scheduled rotation; `ark
  secrets rotation status` and `ark doctor` show overdue keys.
* `ark app token rotate [--token-name NAME]` — a new app token in the secret `[app] token`
  references (`{{secret:APP_TOKEN}}`); restart the daemon afterwards.
* Node device tokens: `node.token.rotate` (or SPIFFE identities, above).

Rotations are recorded in the audit stream (`secret.rotate`) without values.

## Per-team model keys

A session is charged to its owner (`ark users team <id> <team>`); its model calls use the
team's own key when one exists: the secret named like the provider's key variable plus
`__<TEAM>` (upper-case, non-alphanumerics → `_`), e.g. `OPENAI_API_KEY__ENG_PLATFORM` for team
`eng-platform`. Set it in the vault (`ark secrets set`) or bind it from any secret source.
Teams without their own key use the shared one.
