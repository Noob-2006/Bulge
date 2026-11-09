# ARP：SE Agent 統一協議（`seagent/2`）

SE Agent 的每一個介面都講同一套協議：網頁、桌面 App、手機（PWA）、終端機 TUI、腳本、編輯器（ACP 橋接）、裝置（node）。
ARP 是 JSON-RPC 2.0，傳輸層有三種，方法與事件完全相同：

| 傳輸 | 位置 | 驗證 | 用途 |
|---|---|---|---|
| Unix socket（每行一個 JSON） | `$XDG_RUNTIME_DIR/seagent/seagentd.sock`（0600） | 檔案權限 | CLI、TUI、本機腳本 |
| WebSocket | `GET /arp` | `Authorization: Bearer`、`?token=` 或子協議 `seagent.token.<t>` | Web／桌面／手機 UI、遠端用戶端 |
| HTTP | `POST /arp`（一次一個請求） | Bearer | curl、自動化 |

App Server 由 daemon 啟動（`[app] enabled = true`），同一個 port 上另有：
OpenAI 相容 API（`/v1/models`、`/v1/chat/completions`、`/v1/responses`）、A2A（`/a2a/v1`、`/.well-known/agent-card.json`）、裝置（`/node`）、UI（`/`）。

## 握手

WebSocket 連上後，伺服器先送 `ready` 通知；也可以隨時呼叫 `initialize`：

```json
{"jsonrpc":"2.0","method":"ready","params":{"protocol":"seagent/2","server":{"name":"seagent","version":"0.1.0"},
 "methods":["ping","session.list",…],"events":["event","delta","pending","heartbeat"],
 "features":{"openai":true,"a2a":false,"nodes":true,"ui":true}}}
```

## 方法

| 方法 | 參數 | 結果 |
|---|---|---|
| `ping` | — | `{protocol, version, running[], pid}` |
| `session.list` | `limit?` | `[{id,title,model,workspace,updated_ms,messages,parent,running}]` |
| `session.create` | `workspace, model?, title?` | `{id}` |
| `session.submit` | `id, text, source?` | `{queued, started}`；正在執行時會插入目前回合 |
| `session.interrupt` | `id` | `{interrupted}` |
| `session.history` | `id, from_seq?` | 事件陣列（完整紀錄） |
| `session.view` | `id` | `{messages, running, workspace}`（模型看到的對話） |
| `gate.pending` | — | 等待中的核准與提問 |
| `gate.answer` | `id, answer` | 核准：`once`／`always`／`deny`；提問：回答文字 |
| `goal.list`、`goal.start`、`schedule.list` | | 長期目標與排程 |
| `models.list`、`tools.list` | | 模型設定、工具清單 |
| `channels.list`、`mcp.list` | | channel 能力、MCP 狀態 |
| `mcp.app_call` | `server, name, arguments, session?` | MCP Apps 視圖的 `tools/call` 代理：只限伺服器標為 app 可見的工具；非唯讀（或 untrusted 伺服器）先走 egress 核准；回傳 CallToolResult |
| `plugins.ui` | `plugin, id, query?` | 外掛 UI 面板的 HTML：`{html, csp?}`（網頁 UI 以 MCP Apps 同樣的 sandbox srcdoc iframe＋CSP 呈現） |
| `plugins.ui_call` | `plugin, id, method, params?` | 面板 iframe 的 JSON-RPC 請求（postMessage）代理到外掛 `seagent/ui.call` |
| `pairing.list`、`pairing.approve`、`pairing.revoke` | `channel, code` / `channel, sender` | DM 配對 |
| `node.list`、`node.describe`、`node.invoke`、`node.pair.list`、`node.pair.approve`、`node.pair.reject`、`node.remove` | | 裝置 |
| `subscribe` | `{}` 或 `{id, from_seq?}` | 開始串流；有 `id` 時先重播該 session 紀錄 |
| `unsubscribe` | `subscription` | |
| `shutdown` | — | 停止 daemon |

錯誤碼：-32700 解析錯誤、-32600 無效請求、-32601 未知方法、-32602 參數錯誤、-32000 核心錯誤、-32001 找不到項目。

## 事件（伺服器通知）

每個串流訊息的 `params.subscription` 是當初 `subscribe` 請求的 id，用戶端據此分流。

- `event {session, event}`：session 紀錄的每一筆事件（`header`、`message`、`tool_called`、`tool_settled`、`gate`、`turn_start`、`turn_end`、`notice`、`error`…，格式見 `crates/seagent-kernel/src/event.rs`）。MCP Apps 工具的 `tool_settled` 帶 `ui_resource {server, tool, uri, html, csp, permissions, prefersBorder, toolInput, toolResult, path}`，網頁 UI 以 `sandbox="allow-scripts"` 的 srcdoc iframe 呈現，postMessage 橋接 `ui/initialize`、`ui/notifications/initialized`、`ui/notifications/tool-input`／`tool-result`、`tools/call`（→ `mcp.app_call`）、`ui/notifications/size-changed`、`ui/open-link`（需確認）。
- `delta {session, text, thinking}`：串流中的文字或思考增量。
- `pending {kind: approval|question, id, session, …}`：需要人回應。
- `heartbeat`：每 15 秒，兼作斷線偵測。

## 區域網路裝置（LAN 模式，`[app.exposure] lan = true`）

App、手機瀏覽器與其他電腦以 `POST /pair/client` 配對（在憑證檢查之前處理、每個位址限速、結果寫入稽核流）：

```text
{"bootstrapToken": "…", "device": {"id": "<1–64 英數 - _>", "name": "…", "platform": "ios|android|web|…"}}
  → 200 {"consoleToken": "sed1_…", "hostId": "<16 hex>", "name": "<主機名稱>", "deviceId": "…", "scope": "write"}
{"code": "ABCD2345", "device": {…}}                       → 202 {"status": "pending", "requestId", "retryAfterMs", "expiresAtMs", "sas"}
{"code": "ABCD2345", "requestId": "…", "device": {…}}     → 每次最多等 15 秒；核准後 200（同上），拒絕 403
錯誤：400 格式、403 未知／已用／過期、409 配對碼已被別的裝置使用、415 非 JSON、429 太頻繁
```

`bootstrapToken` 來自 setup code（QR／連結，一次性）；8 碼配對碼來自 `seagent pair code` 或主控台「配對裝置」，
只是「申請」，要管理員核准（雙方畫面顯示的短指紋——憑證 SHA-256 前 16 hex、四碼一組——必須相同）。
`consoleToken` 是每台裝置一個、可撤銷的憑證（只存加鹽雜湊，`<data>/devices.json`），用法與 app token 相同
（`Authorization: Bearer`、`seagent.token.<t>` 子協定、WebSocket 升級的 `?token=`、網頁 `#token=`），預設 `write`。
LAN 模式下網路上的連線**只**接受這種 token；撤銷後開著的 WebSocket 一秒內斷線。

**裝置金鑰**（[SECURITY.md §8](SECURITY.md)）：`device` 可帶 `"publicKey": "<base64url 65-byte P-256 點>"`。帶了之後 200
回應另有 `"keyBound": true, "accessToken": "sea1_…", "accessExpiresAtMs"`，而 `consoleToken` **不再能當 bearer**，
只能換 access token：

```text
GET  /pair/info                                   → 200 {"hostId", "nowMs", "protocol", "refresh": true}
POST /pair/refresh   Authorization: Bearer sed1_…
     {"deviceId", "ts": <主機時鐘 ms>, "nonce": "<16–64 url-safe>", "sig": "<base64url r‖s>", "publicKey"?}
     sig = ECDSA-P256-SHA256("seagent-device-refresh|v1|<hostId>|<deviceId>|<ts>|<nonce>")
  → 200 {"accessToken": "sea1_…", "expiresAtMs", "scope", "keyBound": true}
  → 401 錯 token／錯簽章／ts 超出 ±5 分鐘／nonce 重送；409 綁定衝突；429 鎖定中
```

沒有金鑰的舊裝置在 refresh 時帶上 `publicKey` 就完成綁定（一次，之後不可換）。access token 只在記憶體，daemon
重啟後裝置重新 refresh 即可。`devices.list` 的每筆另有 `keyBound`、`boundAtMs`、`lastIp`。

| 方法 | 權限 | 說明 |
|---|---|---|
| `devices.list` | admin | `{devices, pending}`（不含 token） |
| `devices.pending` | admin | 等待核准的配對申請 |
| `devices.approve {code}` / `devices.reject {code}` | admin | 核准／拒絕 |
| `devices.revoke {id}` | admin | 撤銷裝置 |
| `devices.revoke_all` | admin | 登出所有裝置（全部要重新配對）`{revoked}` |
| `devices.scope {id, scope}` | admin | `read`（只能檢視）／`write`（完整操作）／`approve`（也可核准）；下一個請求就生效 |
| `devices.pair.create {ttlMin?, scope?}` | admin | `{setupCode, pairUri, link, url, address, code, expiresAtMs, fingerprint, sas, qrSvg, qrText}` |
| `discovery.list {timeoutMs?}` | read | mDNS 找到的 SE Agent 主機 `{hosts: [{id, name, address, addresses, url, fpPrefix, sas, self}]}`；`addresses` 含 IPv6（link-local 帶 zone，如 `fe80::1%eth0`），`address`／`url` 是最佳的一個 |
| `lan.status` | read | LAN 模式、探索（`discoveryState`：`off`／`advertising`／`limited`／`idle`，含介面與位址）、位址、憑證、已配對裝置數 |
| `lan.probe {address}` | admin | 對方憑證指紋（TOFU 比對用） |
| `lan.connect {address, code \| setupCode, fingerprint?, fpPrefix?, name?}` | admin | 本機以裝置身分配對對方，token 存入 vault，登記為叢集節點（`https://`＋釘選指紋） |

mDNS：`_seagent._tcp.local`，TXT 只有 `v=seagent/2`、`id`、`fp`（指紋前 16 hex）、`name`，從不帶 token。

## 裝置協議（`/node`）

1. 伺服器送 `connect.challenge {nonce}`。
2. 裝置送 `node.connect {id, name, platform, caps, commands, publicKey, signature, deviceToken?, bootstrapToken?}`，`signature` 是 Ed25519 對 `seagent-node|v1|<id>|<nonce>` 的簽章。
3. 新裝置會拿到 8 碼配對碼；管理員 `seagent nodes approve <code>` 後，裝置收到 `node.pair.resolved {deviceToken}`，之後以 token＋簽章連線。帶有效 `bootstrapToken`（setup code，一次性）的新裝置直接核准。
4. 伺服器送 `node.invoke.request {id, command, params, timeoutMs}`，必要時再送 `node.invoke.input {id, seq, data, eof?}`（`system.run {stdin: true}` 的標準輸入）或 `node.invoke.cancel {id}`；裝置回 `node.invoke.progress` 或 `node.invoke.result {id, ok, payload, error}`。
5. 離線佇列：`node.invoke {queue: true, ttlMs?}` 對離線的已配對裝置排隊（預設 10 分鐘）；裝置連上時收到 `node.pending {count}`，呼叫 `node.pending.pull` → `{actions}`，執行後回結果並 `node.pending.ack {ids}`。工作項目 `node.pending.enqueue {nodeId, type: status.request|location.request}`（同型別合併，預設 24 小時）由裝置 `node.pending.drain {maxItems}` 取走。
6. 裝置可送 `node.event {event, payload}`（`node.events` 查詢）；`node.token.rotate {id}` 讓伺服器發 `node.token.rotated {deviceToken}`，舊 token 立即失效。

ARP 方法：`node.list`、`node.describe`（含指令參數 schema）、`node.rename`、`node.invoke`、`node.invoke.cancel`、`node.invoke.input`、`node.pending.enqueue`、`node.queue`、`node.events`、`node.token.rotate`、`node.setup.create`、`node.pair.list/approve/reject`、`node.remove`。

Setup code 與 OpenClaw 相同：base64url(JSON `{url, bootstrapToken, expiresAtMs, tlsFingerprint?}`)。`seagent nodes setup-code [--url ws://…] [--ttl 分鐘] [--tls-fingerprint SHA256]` 在終端機顯示 QR code（byte 模式、EC M、版本 1–15），裝置端 `seagent node --setup-code <code>`；有 `tlsFingerprint` 時裝置在 TLS 握手時只接受該憑證（wss，自簽憑證亦可）。不在 loopback 的 URL 一律是 `wss://`（LAN 模式自動帶指紋），不再產生明文 `ws://` 的區網配對碼。

Linux 裝置：`seagent node --url ws://主機:8640/node`。允許的指令由裝置端 `~/.config/seagent/node.toml` 決定（`run = "deny" | "allowlist" | "full"`、`allow`、`camera`、`screen`（含 `screen.record`，ffmpeg x11grab 或 wf-recorder）、`location`、`computer`（`computer.act`：X11 用 xdotool、Wayland 用 ydotool，預設關）、`canvas`（`canvas.present` 以預設瀏覽器開 URL/HTML）、`notifications`（dunst/mako 的 `notifications.list/actions`）、`read_roots`、`microphone`＋`[stt]`（`talk.ptt.start/stop/cancel/once`：pw-record 或 ffmpeg 錄音，OpenAI 相容 `/audio/transcriptions` 轉寫；`url`、`key` 或 `key_env`、`model`、`language`）、`cdp_url`（computer.act 瀏覽器動作，只接受本機 `http://127.0.0.1:<port>`）、`[plugins.<名>]`（外掛的 `node_commands` 由此裝置提供）），伺服器無法越權。`computer = true` 時 computer.act 也有 v2 動作：`list_apps`、`list_windows`、`get_accessibility_tree`／`get_window_state`、`set_value`、`bring_to_front`、以 `elementRef` 點擊（AT-SPI：有 python3-gi 用 Atspi，否則 `gdbus`）、`launch_app`（`gtk-launch` 桌面項目 id）、`get_browser_state`、`browser_navigate`、`browser_click`、`browser_type`（CDP）。外掛指令在 `node.connect` 以 `commandMeta {指令: {description, dangerous, params}}` 告知伺服器，`node.describe` 顯示其 schema，`dangerous` 者先經 egress 閘門。手機 App 專屬指令（photos、contacts、calendar、reminders、sms…）SE Agent 沒有裝置端，但裝置宣告了就能呼叫，參數依內建 schema 檢查，危險指令一律先經 egress 閘門詢問。

## 版本

`seagent/2` 向下相容 daemon 原本的 `ARP v1`（同樣的 unix socket 方法）；新增的只有方法與欄位，不會改變既有語意。
