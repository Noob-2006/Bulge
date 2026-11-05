# 其他生態（F7）：MCP、ACP、Claude Code、A2A

四個「不是 OpenClaw/Hermes」但實際會被拿來接 SE Agent 的生態。每列都標了本輪實際驗證到什麼程度。

## 1. 對照表

| 生態 | SE Agent 的角色 | 狀態 | 驗證方式 |
|---|---|---|---|
| MCP：官方／第三方 server | **client** | ✅ 直接用 | 實跑 Hermes `optional-mcps` 轉出的 `[mcp.fs]`（`npx @modelcontextprotocol/server-filesystem`）→ `seagent mcp list` 顯示 `running 14 tools` |
| MCP：SE Agent 當 server | **server** | ✅ 直接用 | `printf initialize | seagent mcp serve` → `serverInfo {name: seagent}`、`tools/list` 列出檔案／搜尋／shell／記憶與 `seagent_session_*` |
| MCP：認證（OAuth 2.1 / DCR）、task、events、apps | client | ✅（既有） | `[mcp.<n>] auth = "oauth"`、`seagent mcp login`；`protocol`、`tasks`、`events`、`apps` 設定鍵 |
| ACP：外部 agent（Claude Code、Codex、Gemini、OpenCode、Qwen、Copilot…） | **client** | ✅ 直接用（本輪用腳本化 agent 實測） | `seagent acp-client fake "hello there"` → `echo: hello there [fake · done · session …]`；`[acp.agents.<n>]` 只在使用者設定生效（專案設定需 `trusted_projects`） |
| ACP：SE Agent 當 agent（Zed 等編輯器） | **server** | ✅（既有） | `seagent acp`；`crates/seagent-app/src/acp.rs` |
| ACP：`acp_delegate` 工具 | 兩者 | ✅（既有） | 權限模式 `approve-all`/`approve-reads`/`deny-all`；fs/terminal 請求先過 SE Agent 閘門 |
| Claude Code：skills（`~/.claude/skills`、`.claude/skills`） | 技能來源 | ✅ 直接用 | 實測：在 workspace 放 `.claude/skills/cc-demo/SKILL.md` → `seagent skills list` 顯示 `cc-demo project available`（`allowed-tools` 被忽略） |
| Claude Code：hooks（`settings.json` 的 `PreToolUse`…） | hook 事件名 | ✅ 直接用 | `HookEvent::claude_name()` 讓 hook 腳本收到 `hook_event_name: "PreToolUse"`；`crates/seagent-kernel/src/hooks.rs` 有測試 |
| Claude Code：`settings.json` / `.claude.json`（model、env、mcpServers） | 匯入 | ✅ 經 `seagent migrate from claude` | `ops::migrate::plan_claude`：`mcpServers` → `[mcp.*]`、`model` → `[model]`、金鑰 → vault |
| Claude Code：plugin marketplace（`.claude-plugin/marketplace.json`） | 套件來源 | ✅（既有） | `seagent plugins install <plugin>@<marketplace>`（`hub/plugins.rs`） |
| A2A：SE Agent 當 server | **server** | ✅ 直接用 | 實測：`[app] a2a = {enabled=true}` → `GET /.well-known/agent-card.json` 回 `protocolVersion 1.0`、`capabilities.streaming`、`securitySchemes.bearer` |
| A2A：SE Agent 當 client | **client** | ✅（既有） | `[app.a2a] agents = {peer = {url, token}}` ＋ `a2a_*` 工具 |

## 2. 需要轉換／不支援的細節

- **MCP 的 tools 命名**：外來工具在 SE Agent 內是 `mcp__<server>__<tool>`；反過來 SE Agent 當 server 時工具名
  不變。若某個 MCP client 只認扁平名稱（沒有 `__`），要在 client 端設定，不是 SE Agent 端。
- **MCP server 的 `outputSchema`**：SE Agent 會用內建的 JSON Schema 子集驗證（`seagent_plugin::schema`），
  `pattern`/`format` 不檢查、網路 `$ref` 一律拒絕。
- **ACP 的權限請求**：`approve-reads` 模式下，寫入／執行會問人；沒人能回答時**拒絕**（安全預設）。
  這與 §0 的「卡住只卡那一條」一致：被拒的是那一個請求，不是整個 session。
- **Claude Code 的 `allowed-tools`、`disable-model-invocation`**：SE Agent 沒有對應概念（工具權限由
  SE Agent 的閘門決定），`skills` 匯入時會丟棄並在 `dropped` 列出。
- **Claude Code 的 hook 只支援「命令型」**（`{"type": "command"}`）；其它類型（例如未來的內建型）
  不轉。
- **A2A 的 push notification**：需要 `[app.a2a] push_secret`（HMAC-SHA256 簽章）；沒設就只註冊
  webhook 而不簽章，對方可能拒收。

## 3. 本輪驗證指令（丟棄式 `SEAGENT_HOME`）

```sh
export SEAGENT_HOME=$TMPDIR/f7/home
# MCP client（真的起一個第三方 server）
seagent skills compat import $SEAGENT_UPSTREAM_HERMES/optional-mcps/filesystem   # 或是 seagent migrate from hermes
seagent mcp list                                  # → fs  running  14 tools  stdio  npx -y @modelcontextprotocol/server-filesystem
# MCP server
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}\n' | seagent mcp serve
# ACP client（腳本化 agent，不呼叫任何真實模型）
printf '[acp.agents.fake]\ncommand = "python3"\nargs = ["<repo>/tests/e2e/fake_acp_agent.py"]\n' >> $SEAGENT_HOME/config/config.toml
seagent acp-client fake "hello there"
# A2A server
# config.toml: [app] enabled = true, a2a = { enabled = true, name = "seagent-test" }
curl -H "authorization: Bearer $TOKEN" http://127.0.0.1:8640/.well-known/agent-card.json
```

## 4. 待辦

- MCP 的 `sampling`／`elicitation` 對第三方 server 預設關閉；要逐 server 開（`[mcp.<n>] sampling.enabled`）。
  大規模接入時應該有「一份能力清單一次核准」的批次流程。
- ACP 的 presets 只有名稱與啟動命令，沒有對每個 agent 的版本差異做測試（本輪只驗了協議本身）。
- Claude Code 的 `statusLine`、`permissions.deny` 規則沒有匯入。
