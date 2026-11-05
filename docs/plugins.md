# ark 外掛協議（v1）

外掛是獨立程序，經 stdio 說 **MCP 的超集**（JSON-RPC 2.0，一行一則）。任何 MCP stdio server 都能當外掛；外掛在 `initialize` 結果宣告額外能力，ark 才會送對應的 `ark/*` 請求。比上游（OpenClaw、Hermes 都是同程序載入）多一層程序隔離：外掛崩潰或逾時不會拖垮 agent。

```toml
[plugins.kinds]
command = "python3"
args = ["/path/to/plugin.py"]
timeout_secs = 60        # 一般請求逾時；provider 至少 120 s
```

完整範例（每種註冊都有）：`tests/fixtures/plugin/kinds.py`。`ark plugin list` 列出每個外掛提供的東西。

## 宣告

```json
{"capabilities": {"tools": {}, "experimental": {"ark": {
  "version": 1,
  "hooks": ["pre_tool", "message_sending"],
  "channels": ["mychat"],
  "commands": [{"name": "weather", "description": "查天氣", "args": "<城市>"}],
  "routes": [{"path": "/hook", "methods": ["POST"], "public": true}],
  "providers": [{"id": "local", "models": ["m1"], "context_window": 32000, "max_output": 4096, "tools": false, "vision": false}],
  "services": [{"name": "indexer", "health_secs": 30}],
  "cli": [{"name": "kb", "description": "知識庫", "args": "<sub> …"}],
  "middleware": ["tool_request", "tool_execution", "llm_request", "llm_execution"],
  "context_engine": {"owns_compaction": true},
  "memory": true,
  "backends": [{"kind": "tts", "id": "acme", "label": "Acme Voice", "caps": {"voices": ["en-US-1"]}}],
  "dashboard_auth": {"id": "acme-sso", "label": "Acme SSO"},
  "node_commands": [{"command": "kb.search", "description": "…", "dangerous": false, "params": {"type": "object"}}],
  "ui": [{"id": "dash", "title": "知識庫", "surface": "tab"}]
}}}}
```

## 工具、資源、提示

即 MCP：`tools/list`、`tools/call`、`resources/*`、`prompts/*`。工具名稱為 `mcp__<外掛>__<工具>`，經過同樣的閘門。

## Hook（`ark/hook`）

ark → 外掛：`{"event": "<事件>", "payload": {...}}` → `{"decision": "allow" | "deny" | "modify", "reason"?, "input"?}`。
`payload.input` 是可改寫的部分（工具參數或文字）；`modify` 以 `input` 取代。錯誤或逾時（5 s）一律視為 allow 並警告。

| 事件 | 時機 | 可 deny / modify | 上游別名（也接受） |
|---|---|---|---|
| `session_start` / `session_end` | 建立 session／刪除、`/new`、`/forget`、保存期限到期、chat 結束 | — | `on_session_start`、`on_session_end` |
| `user_prompt` | 使用者輸入進 session 前 | deny、modify 文字 | `user_prompt_submit`、`before_prompt_build` |
| `pre_tool` / `post_tool` | 工具前／後 | pre：deny、modify 參數 | `pre_tool_call`、`before_tool_call`、`after_tool_call` |
| `pre_model` / `post_model` | 每次模型請求前／回應後（`model`、`messages`、`text`、`usage`） | pre：deny（該步失敗） | `pre_llm_call`、`llm_input`、`post_llm_call`、`llm_output` |
| `pre_compact` / `post_compact` | 摘要壓縮前／後（`tokens_before`） | pre：deny（略過這次壓縮） | `before_compaction`、`after_compaction` |
| `message_received` | channel 訊息通過存取檢查後（`channel`、`chat`、`sender`） | deny（丟棄）、modify 文字 | `inbound`、`before_dispatch`、`pre_gateway_dispatch` |
| `message_sending` / `message_sent` | channel 回覆送出前／後 | sending：deny（不送）、modify 文字 | `outbound`、`reply_payload_sending` |
| `subagent_start` / `subagent_stop` | 子代理開始／結束（`subagent_id`、`task`、`end_reason`） | start：deny | `subagent_spawned`、`subagent_ended` |
| `notification` | 需要人：核准請求、提問（`kind`、`message`） | — | |
| `turn_end` | 一輪結束（`end_reason`、`last_assistant_message`） | — | `agent_end`、`stop` |
| `daemon_start` / `daemon_stop` | arkd 啟動／停止 | — | `gateway_start`、`gateway_stop` |
| `pre_approval_request` / `post_approval_response` | 閘門要人核准前／人回答後（`gate`、`reason`、`tool_input`；post 加 `choice`：once／always／deny） | — | |
| `human_input_request` / `human_input_resolved` | agent 問人前／得到答案後（`message`；resolved 加 `answer`、`cancelled`） | — | `on_human_input_request`、`on_human_input_resolved` |
| `transform_tool_result` | 工具結果交給模型前（`input` = 結果文字） | modify 取代 | |
| `transform_terminal_output` | `shell` 工具輸出（在 transform_tool_result 之前；`command`） | modify 取代 | |
| `transform_llm_output` | 模型回覆（`input` = 文字；已串流到畫面的仍是原文，紀錄與後續脈絡用新文字） | modify 取代文字區塊 | |
| `transform_api_error` | 模型呼叫失敗（`input` = `{kind, message, retryable, fallback}`） | modify 改 `retryable`／`fallback` | `transform_api_error_classification` |

Hermes 的 kanban 事件（`kanban_task_*`、`on_kanban_*`）沒有對應：ark 沒有 kanban 看板，不註冊無觸發點的事件（與 Hermes 自己的規則相同）。

同樣的事件也可用於 `[[hooks]]` shell hook（`event = "pre_compact"`；stdin 收 JSON，`hook_event_name` 為 Claude Code 風格名稱）。

## Middleware（`ark/middleware`，Hermes）

外掛在 `middleware` 宣告要的種類；ark → 外掛 `{"kind", "phase"?, "payload"}`，回覆裡有對應鍵就取代，沒有就不變。逾時（請求類 5 s、執行類 30 s）或錯誤一律略過並警告。

| kind | 時機 | payload | 回覆 |
|---|---|---|---|
| `tool_request` | 工具參數，在 pre_tool hook 與閘門之前 | `tool_name`、`args` | `{"args": {...}}` 改寫參數 |
| `tool_execution` | `phase: "call"`：通過閘門、執行前；`"result"`：執行後 | `tool_name`、`args`、`result`（result 階段） | `{"result": {"content", "is_error"} \| "文字"}`：call 階段＝不執行工具直接用這個結果；result 階段＝取代結果 |
| `llm_request` | 每次模型請求前 | `model`、`request`（ark ModelRequest） | `{"request": {...}}` |
| `llm_execution` | `phase: "call"`：呼叫 provider 前；`"result"`：回應後 | `request`、`response`（result 階段） | `{"response": ModelResponse \| {"text"}}`：call 階段＝不呼叫 provider |

Hermes 的執行類 middleware 是包住 `next_call()` 的函式；跨程序做不到，所以拆成 call／result 兩次呼叫（短路＝call 階段給結果）。

## CLI 子指令（`ark/cli`，OpenClaw `registerCli`）

`ark <name> 參數…`：內建指令名稱不能被占用；參數（含 `--旗標`）原樣傳給外掛。`ark help` 列出外掛指令。
ark → 外掛：`{"name", "argv": [...], "cwd", "run_id"}`；執行中可送通知 `ark/cli.output {"run_id", "stream": "stdout"|"stderr", "text"}`；最後回 `{"stdout"?, "stderr"?, "exit"?}`（`exit` 成為 ark 的結束碼）。逾時：`timeout_secs` 與 600 s 取大。

## Context engine（`ark/context.*`，OpenClaw `ContextEngine`）

設定 `context_engine = "<外掛>"`。每次模型請求前 `ark/context.assemble {"session", "workspace", "messages", "token_budget", "model", "prompt", "bootstrap"}`（該 session 第一次為 `bootstrap: true`，對應 OC 的 `bootstrap`）→ `{"messages"?, "system_prompt_addition"?}`；`messages` 必須以 user 開頭與結尾，否則用 ark 自己的歷史並警告。每則訊息寫入紀錄時送通知 `ark/context.ingest {"session", "message"}`。宣告 `owns_compaction` 時，壓縮（門檻到了、`/compact`、context overflow）改呼叫 `ark/context.compact {"session", "messages", "token_budget", "current_tokens", "force"}` → `{"compacted": bool, "summary", "keep_messages"?}`：摘要寫進 ark 的事件紀錄；`compacted: false` 表示這次不壓縮。失敗一律退回 ark 的行為。

## Memory provider（`ark/memory.*`，Hermes MemoryProvider）

設定 `[memory] provider = "<外掛>"`：內建的 `memory` 工具（MEMORY.md／USER.md）換成外掛版，動作 `read`、`search`（`query`）、`add`、`replace`、`remove`。
ark → 外掛：`ark/memory.call {"action", "file": "memory"|"user", "text"?, "old"?, "query"?, "session"}` → `{"text"}` 或 `{"error"}`。啟動時 `ark/memory.prompt {}` → `{"text"}` 加進身分段（Hermes `system_prompt_block`，靜態）。

## 能力後端（`ark/backend.call`，Hermes `register_*_provider`）

一個外掛可以提供 ark 內建工具背後的一種後端，於 `capabilities.experimental.ark.backends` 宣告（`kind` = `tts`、`stt`、
`image_gen`、`video_gen`、`browser`、`web_search`；`id` 就是 config 用來選它的名字，內建名稱如 `openai`／`brave`／`browserbase`
永遠保留給內建 provider）。只有設定指名時才會用到外掛（`[media.tts] provider`、`[media.stt] provider`、`[media.image] provider`、
`[media.video] provider`、`[browser] cloud_provider`、`[web.search] provider`），`auto` 永遠不會挑外掛。

ark → 外掛：`ark/backend.call {"kind", "id", "op", "params"}` → 廠商 envelope，或 `{"error": "…"}`。
`op` 依 kind：`tts` 的 `synthesize`（回 `{"audio_base64", "mime"?, "sample_rate"?}`）、`stt` 的 `transcribe`（回 `{"text", "language"?, "duration"?}`）、
`image_gen`／`video_gen` 的 `generate`、`browser` 的 `create_session`／`close_session`／`cleanup`、`web_search` 的 `search`／`extract`。
完整 payload 見 `ark_plugin::backends` 的文件。

## Dashboard 登入（`ark/auth.*`，Hermes `dashboard_auth`）

外掛宣告 `dashboard_auth`（`true` 或 `{"id", "label"}`）後，`[app.auth] provider = "<id>"` 就由它負責登入。
ark → 外掛：`ark/auth.login_start {"redirect_uri"}` → `{"url", "state"}`；`ark/auth.exchange {"code", "state", "redirect_uri"}` → session；
`ark/auth.verify {"token"}` → session；`ark/auth.refresh {"token"}` → session。session 形狀
`{"subject", "email"?, "name"?, "expires_at"?, "admin"?}`；`{"error": "…"}` 表示這個憑證不被接受。
內建 provider：`basic`（`[app.auth.basic.users]` 的帳密）與 `self_hosted`（通用 OIDC，Authorization Code + PKCE）。

## Node 指令（`ark/node.invoke`，OpenClaw `registerNodeHostCommand`）

在 `ark node` 那台機器的 `node.toml` 設 `[plugins.<名>]`（格式同 config.toml）；外掛宣告的 `node_commands`（不可與內建指令同名）加入該裝置提供的指令，並以 `commandMeta` 告知伺服器描述、參數 schema 與 `dangerous`（true 時 agent 呼叫前先經 egress 閘門）。
伺服器 → 裝置 → 外掛：`{"command", "params"}` → 任何 JSON（即 invoke 結果）；`{"error": "…"}` 視為失敗。

## UI 面板（`ark/ui.*`，OpenClaw control UI descriptor）

宣告 `ui: [{"id", "title", "surface": "tab"|"settings"}]`。網頁 UI 側欄（tab）或設定視窗（settings）列出面板，點開時經 ARP `plugins.ui` 取 `ark/ui.render {"id", "query"}` → `{"html", "csp"?: {"connectDomains", "resourceDomains"}}`，放進 `sandbox="allow-scripts"` 的 srcdoc iframe（與 MCP Apps 同樣的 CSP 與 nonce），不能讀 UI 的 token。面板以 postMessage 送 JSON-RPC，網頁 UI 經 ARP `plugins.ui_call` 轉成 `ark/ui.call {"id", "method", "params"}`。也可直接以 `GET /plugins/<外掛>/ui/<id>` 開啟（需 app token，回應加 `Content-Security-Policy: sandbox`）。

## Channel（`ark/channel.*`）

- 出站 ark → 外掛：`ark/channel.send {channel, message: Outbound}` → `{message_id?}`。
- 入站 外掛 → ark 通知：`ark/channel.inbound {channel, message: Inbound}`。
- 設定：`[channels.<名稱>] kind = "plugin"`、`plugin = "<外掛>"`。

## 指令（`ark/command`）

在 chat、TUI、`ark run /名稱`、各 channel 都可用 `/名稱 參數`。
ark → 外掛：`{"name", "args", "context": {"surface": "chat" | "tui" | "cli" | "channel", "session"?, "channel"?, "chat"?, "sender"?}}`
→ `{"text"?: 直接回給使用者, "prompt"?: 當成使用者訊息交給 agent}`（兩者可同時）。TUI 經 ARP `command.run` 呼叫。

## HTTP 路由（`ark/http`）

掛在 App Server 的 `/plugins/<外掛>/<path>`（需 `[app] enabled`）。`path` 是前綴；`methods` 空表示全部。
預設需要 app token；`public: true` 免 token（例如自行驗章的 webhook）。`Authorization`、`Cookie` 不會轉給外掛；回應一律加上 `Content-Security-Policy: sandbox`（外掛頁面與 UI 同源，不能讀 UI 的 token）。
ark → 外掛：`{"method", "path"（去掉前綴 /plugins/<外掛>）, "query", "headers", "body" | "body_base64"}`
→ `{"status", "headers": {...}, "body" | "body_base64"}`。逾時 30 s，失敗回 502。

## 模型 provider（`ark/provider.complete`）

宣告的 `id` 加入模型登錄，設定裡寫 `model.default = "<id>/<模型>"`（優先於同名內建 preset）。
ark → 外掛：`{"provider", "stream_id", "request": ModelRequest}`（`model`、`system[]`、`messages[]`、`tools[]`、`max_tokens`）。
串流：外掛送通知 `ark/provider.delta {"stream_id", "text"?, "thinking"?}`；最後回 `ModelResponse`（`{"message": {"role": "assistant", "content": [...]}, "stop": "end_turn" | "tool_use" | "max_tokens", "usage", "model"}`）或簡寫 `{"text"}`；`{"error": "…"}` 視為 400。

## 背景服務（`ark/service.*`）

只在 daemon 執行：啟動時 `ark/service.start {name}`，每 `health_secs`（預設 60）`ark/service.health {name}` → `{"ok": bool, "detail"?}`；連續兩次不健康（或無回應）就 `stop` + `start` 重啟；daemon 停止時 `ark/service.stop`。

## 其他

- 外掛 stderr 只留在環形緩衝供診斷，不進模型脈絡。
- 外掛呼叫 ark 未知的 `ark/*` 方法得到 -32601。
- 一個外掛程序同時處理所有種類；忙碌中的請求依序排隊（需要並行請自行多執行緒）。
