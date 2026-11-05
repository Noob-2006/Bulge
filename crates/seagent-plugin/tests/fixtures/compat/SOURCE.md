# Compat fixtures — provenance

Every fixture here is either copied (and trimmed) from a read-only upstream checkout or
written for this crate; nothing was downloaded and no upstream file was modified.

| Fixture | Source | Upstream commit | Notes |
| --- | --- | --- | --- |
| `openclaw-node/openclaw.plugin.json`, `package.json`, `index.js`, `skills/demo/SKILL.md` | `$SEAGENT_UPSTREAM_OPENCLAW/dist/extensions/*` (`openclaw.plugin.json` shape of `brave`, `browser`, `advisor`) | `555c0182e4d064b3f372da085c09375a1cafbef4` | Written for the fixture: same keys and nesting (`activation.onStartup`, `cliCommands`, `setup.providers[].envVars`, `contracts.*`, `configSchema`, `skills`), but synthetic ids so it cannot be confused with a real extension. The `index.js` is a hand-written `definePluginEntry`-shaped stub: it does **not** import `openclaw/plugin-sdk`, so the shim's `register(api)` path can be exercised. |
| `openclaw-declarative/openclaw.plugin.json` | same corpus (`channels`, `contracts.channelProviders`) | `555c0182e4d064b3f372da085c09375a1cafbef4` | Written for the fixture; declares no code so the declarative branch (and a skill path that escapes the plugin dir) is covered. |
| `hermes-python/plugin.yaml` | `$SEAGENT_UPSTREAM_HERMES/plugins/security-guidance/plugin.yaml` + `plugins/google_meet/plugin.yaml` (`provides_tools`, `kind`) + `plugins/model-providers/*/plugin.yaml` (`requires_env`) | `0319e113c9602b86ffda350e931cb4b035e1d5d8` | Fields and nesting kept; name/ids synthetic. `experiment_hook` under `provides_hooks` is added on purpose: no SE Agent hook event has that name, so the importer must report it instead of inventing a mapping. |
| `hermes-python/__init__.py` | shape of `plugins/security-guidance/__init__.py` (`register(ctx)`, `_on_pre_tool_call` returning `{"action": "block", ...}`) | `0319e113c9602b86ffda350e931cb4b035e1d5d8` | Written for the fixture (no Hermes imports run). |
| `hermes-python/SKILL.md` | shape of `hermes-agent/skills/**/SKILL.md` | `0319e113c9602b86ffda350e931cb4b035e1d5d8` | Written for the fixture. |
| `hermes-provider/plugin.yaml` | `$SEAGENT_UPSTREAM_HERMES/plugins/model-providers/anthropic/plugin.yaml` | `0319e113c9602b86ffda350e931cb4b035e1d5d8` | Copied verbatim (5 lines). `__init__.py` written for the fixture. |
| `hermes-hooks-only/plugin.yaml` | `$SEAGENT_UPSTREAM_HERMES/plugins/disk-cleanup/plugin.yaml` | `0319e113c9602b86ffda350e931cb4b035e1d5d8` | Copied verbatim (hooks only, no code → declarative). |
| `hermes-mcp-oauth/manifest.yaml` | `$SEAGENT_UPSTREAM_HERMES/optional-mcps/asana/manifest.yaml` — the only catalog entry with an `auth.oauth` block and `auth.env` prompts | `0319e113c9602b86ffda350e931cb4b035e1d5d8` | Trimmed: comment prose removed, names/urls changed to `demo-oauth` / `example.com`. Structure (`transport`, `auth.env`, `auth.oauth`, `tools.default_excluded`, `suggest`, `post_install`) unchanged. |
| `hermes-mcp-stdio/manifest.yaml` | synthesised | — | No entry in `optional-mcps/` uses `transport.type: stdio` (all 65 are URL-only), so this pins that branch (`command`/`args`/`env`, `${VAR}` → `{{secret:VAR}}`). It is not upstream data and says so in its own header. |
