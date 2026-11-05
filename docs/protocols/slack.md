# Slack API：官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ ark

> **驗證狀態：ark 未對真實 Slack 驗證。** 沒有 bot token／app token／signing secret；ark 行為僅由原始碼與 `FakeServer` + scripted WebSocket 測試佐證（`slack.rs` 的 `#[cfg(test)]`，`:1422` 起，覆蓋 envelope ack、`X-Slack-Signature`、`url_verification`、429 `Retry-After`、upload v2、模態、`block_suggestion`）。真實 Socket Mode 輪替與 rate tier 未測。
> 比較來源：`api.slack.com/apis/connections/socket`、`api.slack.com/events-api`、`api.slack.com/methods/chat.postMessage`、`api.slack.com/authentication/verifying-requests-from-slack`（皆為本次抓取並逐條核對）＋ 上游原始碼。
> 圖例：❓ = 未確認；`—` = 該專案無此通道。

**opencode**：無此通道。`/home/noob/.cache/ark-build/r5-e/opencode` 的 36 個 `packages/` 皆為 coding-agent 元件，全 repo 搜 `slack.com/api`、`chat.postMessage` 0 命中；`slack` 只出現在 SDK 的「使用者自寫 plugin」範例（`packages/sdk/README.md:38`）與 cron 範例的 `tools.slack.read_thread`（`packages/schema/src/schedule.ts:196`），不是協定實作。下表 opencode 欄一律 `—`。

## 對照表

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | opencode | ark |
|---|---|---|---|---|---|
| 傳輸與端點 | Socket Mode：`xapp-` app token + `connections:write`，用 `apps.connections.open` 換取**會輪替**的 WebSocket URL；或 HTTP Events API 由 Slack POST 到 Request URL（`connections/socket`、`events-api`） | `@slack/bolt` 5.1.0（`package.json:11`），預設 `mode = "socket"`、可切 `http`（`src/accounts.ts:171`）；HTTP 模式才需 `signingSecret`（`src/account-inspect.ts:105`） | `slack_bolt.AsyncApp` + `AsyncSocketModeHandler`，**只支援 Socket Mode**（`slack/adapter.py:2`、`:20-22`、`:1013-1017`） | — | 兩者都自寫：有 `app_token` 走 Socket Mode（`apps.connections.open`，`slack.rs:397`），否則要 `listen` + `signing_secret` 走 Events API（`:1379-1420`，預設路徑 `/slack/events`，`:1333-1335`）；不可併用（`:1413`） |
| 認證 | Bot token `xoxb-` 以 `Authorization: Bearer` 送出；Socket Mode 另需 `xapp-` app token | botToken／appToken／signingSecret 三件組（`src/account-inspect.ts:32-40`） | `SLACK_BOT_TOKEN` + `SLACK_APP_TOKEN`（`adapter.py:1014`） | — | `bot_token` 必填（`slack.rs:1337`、`:1381`）；`app_token` 選填（`:1340`、`:1382`）；只支援 bot token，無 `xoxp` user token |
| 入站訊息事件 | `event_callback` 包在 envelope 內；另有 `app_mention`、`message_changed`、`block_actions`、`view_submission`、`slash_commands`（`events-api`） | bolt 事件訂閱 + socket-mode envelope 守衛（`src/monitor/provider-support.ts:13`、`src/socket-mode-envelope.ts`） | bolt `@app.event`／`@app.command`；Socket Mode 重播有 dedup TTL（`adapter.py:881`、`:1073-1075`） | — | DM／群組 DM／頻道／thread（`thread_ts`）、`app_mention`、`message_changed`、檔案、bot 自己開的 thread 回覆（`slack.rs:4-15`、`:602-667`）；`block_actions`→`Callback`、slash→`/cmd text`、`view_submission/closed`→訊息（`:724-783`）；自己的訊息丟棄 |
| 出站訊息格式 | `text` 可用 mrkdwn；有 `blocks` 時 `text` 變通知 fallback；`thread_ts` 決定是否回覆（`methods/chat.postMessage`） | Block Kit 渲染 + 純文字 fallback（`src/blocks-render.ts`、`src/native-data-fallback.ts`） | `block_kit.py` 的 `render_blocks`／`sanitize_blocks`（`adapter.py:58`、`:77`） | — | Markdown → mrkdwn（`Markup::SlackMrkdwn`，`slack.rs:879`；規則 `markup.rs:98-168`）；`mrkdwn` 只在 Markdown 模式開、`unfurl_links: false`（`:1227`） |
| 長度上限與分段 | `text` 建議 ≤4000 字元，>40000 截斷並回 `message_truncated`；用 blocks 時各 block 另有上限（`methods/chat.postMessage`） | `SLACK_TEXT_LIMIT = 8000`、建議 4000、`chat.update` **4000 位元組**、硬上限 40000（`src/limits.ts:1-14`）；blocks ≤50（`src/blocks-input.ts:3`）、section 3000（`src/native-data-fallback.ts:16`） | `MAX_MESSAGE_LENGTH = 39000`，直接切 39000 一段（`adapter.py:1017`、`:1021`） | — | `MAX_MESSAGE = 4000`，有按鈕時降為 `MAX_SECTION = 3000`（`slack.rs:50-51`、`:1219`）；`chunk::split(..., LenUnit::Chars)`（`:1220`）；`edit()` 只 `truncate_chars(…,4000)`（`:1254`） |
| 速率限制 | Web API 依 method tier 限流，429 附 `Retry-After`；`chat.postMessage` 約每頻道 1 msg/s（`docs.slack.dev` rate limits，本次未抓 ❓） | client 層退避（`src/client.rate-limit.test.ts` 對應實作）、上傳另有 `send.upload-rate-limit.test.ts` | 交 slack_sdk + per-call 錯誤分類（`adapter.py:450`） | — | 429 或 `error="ratelimited"` → `RateLimited`；`Retry-After` ≤60s 就地等、>60s 上拋（`slack.rs:160-178`、`:205-212`，測試 `:1711-1727`）；無全域配額、無 tier 概念 |
| 重連與重試 | Socket Mode URL 會輪替；`disconnect` 代表要重連（關閉 Socket Mode 亦然），並可能在 10 秒前先警告（`connections/socket`） | 重連 2s 起、×1.8、上限 30s、jitter 0.25（`src/monitor/reconnect-policy.ts:9-14`）；偵測 `num_connections` 共用連線並警告（`:20-60`） | Socket Mode task 清理 + 重播 dedup（`adapter.py:829-856`、`:1073-1075`） | — | `apps.connections.open` 失敗即退避重連（1s 起、×2、上限 30s、jitter 0.2，`slack.rs:386-424`）；`disconnect` 且 `reason=link_disabled`→`Fatal`，其餘重連（`:474-481`）；自送 ping 每 30s，錯過 pong 重連（`:425-458`） |
| 錯誤碼處理 | HTTP 200 + `{"ok":false,"error":"…"}`；常見 `invalid_auth`、`channel_not_found`、`ratelimited`、`invalid_blocks` | `src/errors.ts` + auth 錯誤 regex（`src/monitor/reconnect-policy.ts:3-5`） | 讀 `exc.response["error"]`，不靠字串比對（`adapter.py:450`） | — | `invalid_auth/not_authed/token_revoked/token_expired/account_inactive/no_permission/missing_scope/…`→`Auth`；`channel_not_found/not_in_channel/is_archived/message_not_found/…`→`NotFound`；5xx 與 `internal_error`→`Network`；其餘→`Protocol`（`slack.rs:160-178`，測試 `:1711-1747`）；Auth 錯誤會讓 Socket Mode 直接停（`:400-403`） |
| 簽章/驗證 | `X-Slack-Signature` = `v0=` + HMAC-SHA256(`v0:<ts>:<body>`)，時間差 >5 分鐘視為重播；Socket Mode 是預先認證的 WebSocket，**不需**驗簽（`authentication/verifying-requests-from-slack`、`connections/socket`） | HTTP 模式由 bolt 驗簽；Socket Mode 靠 app token | 只用 Socket Mode，無驗簽程式 | — | 自算 `v0:ts:body` HMAC-SHA256 + `ct_eq`，誤差 >300s 拒絕（`slack.rs:492-502`）；缺 header／壞時間戳一律 401（`:515-516`）；`url_verification` 回 challenge（`:543`） |
| 媒體 | 上傳走 `files.getUploadURLExternal` → PUT → `files.completeUploadExternal`；私有檔需帶 token 下載 `url_private` | `src/actions.ts` 的 download/upload file actions（`src/actions.download-file.test.ts`） | 檔案事件 + `files_upload_v2` ❓（未逐一核對） | — | upload v2 三步（`slack.rs:888-911`）；單檔且文字 ≤3000 時文字併成 file comment（`:1211-1217`）；下載帶 `Bearer` 並偵測 HTML 登入頁 → 提示缺 `files:read`（`:1303-1312`）；`F…` id 走 `files.delete`（`:1259-1262`） |
| 互動元件 | Block Kit `actions`（每 block ≤5 個 element）、`static_select`、`external_select` + `block_suggestion`、`views.open/push`、`response_url` 延後回覆 | Block Kit 建構 + modal（`src/blocks-render.ts`、`src/actions.blocks.test.ts`）、slash 指令（`src/actions.ts`） | `block_kit.py` + slash payload 模組（`adapter_slash_payload.py`、`adapter_slash_lane.py`） | — | 按鈕列 >5 轉 `static_select`、>100 選項轉 `external_select` 並在 ack 內回 `block_suggestion`（`slack.rs:55-57`、`:810-838`、`:461-472`）；picker 直通（`:63`）；`modal:<name>` 開 `views.open/push`（`:913-950`）；`ack_callback` 先 `response_url` 再退回 `chat.postEphemeral`（`:1283-1301`、`:952-960`） |
| 已知差異 | — | 唯一有 blocks ≤50／section 3000 明確上限的實作者 | 唯一只有 Socket Mode、且用 39000 一刀切 | 無此協定 | 唯一不靠 SDK 自寫 envelope／驗簽；長度用官方建議值 4000 |

## ark 的選擇與差異

- **兩種入站模式互斥、由設定決定。** `app_token`（Socket Mode）或 `listen` + `signing_secret`（Events API），同時給就報錯（`slack.rs:1408-1416`）；OC 用 `mode` 欄位（`accounts.ts:171`），HE 完全沒有 HTTP 模式（`adapter.py:1013-1017`）。
- **envelope 先 ack 再處理。** 收到任何 envelope 立即回 `{"envelope_id": …}`，`block_suggestion` 的答案直接塞進同一個 ack（`slack.rs:461-472`），照官方「3 秒內回應否則重送、共重試 3 次（立即／1 分／5 分）」的規則（`events-api`）。
- **驗簽自寫且嚴格。** `v0:<ts>:<body>` HMAC-SHA256、`ct_eq`、300 秒視窗（`slack.rs:492-502`）；OC 交給 bolt，HE 不需驗（只用 Socket Mode）。
- **長度取官方建議值 4000。** `MAX_MESSAGE = 4000`（`slack.rs:50`），有按鈕時 3000（`:51`、`:1219`）；HE 直接 39000（`adapter.py:1017`）、OC 8000（`src/limits.ts:1`）。ark 寧可多切幾則，也不碰 40000 截斷線（官方 `chat.postMessage#truncating`）。
- **`chat.update` 以字元而非位元組計。** `truncate_chars(text, 4000)`（`slack.rs:1254`）；OC 註解記錄實測是「4000 UTF-8 bytes」（`src/limits.ts:8-10`），所以 4000 個中文字約 12000 bytes → ❓ 可能被 Slack 拒絕（未測）。
- **typing 只在 thread 內可行。** `typing()` 無 thread 直接回 `unsupported`（`slack.rs:1267-1270`）：bot 沒有一般 typing indicator，只能用 `assistant.threads.setStatus`。
- **按鈕過多自動降級。** >5 顆轉 `static_select`、>100 選項轉 `external_select` 並用 ack 回選項（`slack.rs:810-838`、`:461-472`）；選項存本地 30 分鐘（`:58-59`）。這是 ark 自訂規則，OC/HE 沒有對應。
- **原生串流是選配。** `native_streaming = true` 且有 thread 才走 `chat.startStream/appendStream/stopStream`（`slack.rs:1142-1153`、`:1082-1109`），預設仍編輯既有訊息（`:1134`）；OC 無此路徑。
- **callback 回覆兩段 fallback。** 先 `response_url`（ephemeral、不替換原訊息），失敗或缺失才 `chat.postEphemeral`（`slack.rs:1283-1301`）。
- **檔案下載會認出「登入頁」。** 回傳 HTML 就判定缺 `files:read` scope 並報 `Auth`（`slack.rs:1303-1312`），避免把登入頁當檔案內容。
- **未測真實服務。** 以上全由 `FakeServer`／scripted socket 覆蓋（`slack.rs:1422` 起）；真實 Socket Mode 輪替、rate tier、`chat.update` 位元組上限未驗證。

## 抓取備註與證據

- `events-api` 明載：必須 3 秒內回 2xx，否則視為失敗並重試 3 次——第一次幾乎立即、第二次 1 分鐘後、第三次 5 分鐘後，並以 `x-slack-retry-num`／`x-slack-retry-reason` 標示；可用 `x-slack-no-retry: 1` 要求停止重試。ark 的 Events 模式是「先入佇列再回 200」（`slack.rs:520-552`），沒有處理重試標頭。
- `connections/socket` 明載：Socket Mode 不需驗簽（「you're receiving the events over a pre-authenticated WebSocket」），但每個 envelope 都要 ack；`disconnect` 可能在 10 秒前先收到警告，關閉 Socket Mode 時也會收到。ark 只特別處理 `reason=link_disabled`（`slack.rs:474-481`）。
- `verifying-requests-from-slack` 的簽章基准字串是 `v0:<timestamp>:<raw body>`，時間差 >5 分鐘視為重播；ark 用同一公式但收緊到 300 秒（`slack.rs:492-502`）。
- `chat.postMessage` 的截斷規則：建議 ≤4000 字元、>40000 會被截斷且回應帶 `message_truncated`；用 blocks 時 `text` 只當通知 fallback。ark 一律同時送 `text` 與 `blocks`（`slack.rs:1227-1240`），符合 fallback 建議。
- ark 的 Blocks 只在有按鈕或圖片時才建立（`slack.rs:1231-1240`），純文字訊息不包 section block——與 OC 的 `blocks` 優先策略不同，好處是避開 3000 字元 section 上限。
- ark 的 `mrkdwn: true` 只在 `TextFormat::Markdown` 時設（`slack.rs:1227`）；Plain 模式仍會經過 `markup::convert(..., Markup::Plain)`（`:879`、`markup.rs:101-118`），即剝除標記而非原樣送出。
- HE 只用 Socket Mode 且 `MAX_MESSAGE_LENGTH = 39000`（`adapter.py:1017`），等於一條訊息直接吃下 40000 截斷線前的全部內容；ark 選 4000 會讓長回覆變成多則訊息，但每則都能在通知中完整顯示。

## 尚未驗證

- `chat.update` 的 4000 **位元組**上限（OC 註解的主張，`src/limits.ts:8-10`）：ark 以字元計，CJK 內容可能超限。
- Socket Mode URL 輪替頻率與 `disconnect` 後重連的實際節奏（ark 1s→30s 退避）。
- Web API 的 method tier 與 `chat.postMessage` 每頻道 1 msg/s 的實際觸發（ark 只被動接 429）。
- `external_select` 的 100 選項上限與 `block_suggestion` 在真實 Slack 的 3 秒時限內能否完成（ark 從本地快取答，`:461-472`）。

## ark 的 caps() 宣告

- `chat_types = [Direct, Group, Thread]`（`slack.rs:1123`）：**沒有 `Channel`**，因為 Slack 頻道訊息一律映射成 `Group`（`slack.rs:559-567` 的 `chat_type_of`），OC 另有 channel 型別判斷（`src/channel-type.ts`）。
- `reactions = 20`、`polls = false`、`native_commands = true`、`streaming = Native|Edit`（`slack.rs:1127-1134`）；Slack 沒有投票 API，故 `polls = false` 與 OC 一致。
- `max_len = 4000`、`len_unit = Chars`、`markup = SlackMrkdwn`（`slack.rs:1135-1137`）——與 `caps()` 一致的切分因此由 host 直接沿用同一個 4000。
