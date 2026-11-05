# LINE Messaging API：官方規格 ↔ OpenClaw ↔ Hermes ↔ opencode ↔ SE Agent

> **驗證狀態：SE Agent 未對真實 LINE 官方帳號驗證。** 沒有 channel secret、沒有 channel access token、沒有 LIFF/圖文選單；SE Agent 行為僅由原始碼與 `FakeServer` 測試佐證（該測試覆蓋簽章、reply→push 降級、retry key、`X-Line-Retry-Key` 的 409 去重）。真實環境的 reply token 時效與圖文選單互動未測。
> 比較來源：`developers.line.biz/en/reference/messaging-api/`（本次 `web_fetch` 只取到導覽外殼，站台為 JS 渲染，故逐條規格以原始碼與公開文件為準，未能核對者標 ❓）＋ 上游原始碼。
> 圖例：❓ = 未確認；`—` = 該專案無此通道。

**opencode**：無此通道。`$HOME/.cache/seagent-build/r5-e/opencode` 的 `packages/` 無 channel/bot 模組；`grep -rIl -iE "line-bot|messaging api" packages/*/src` → **0 命中**（`line\.me` 的命中都是 `timeline.messages` 這類變數名稱的誤匹配）；`README.md:20` 自述為 coding agent。下表 opencode 欄一律 `—`。

## 對照表

| 面向 | 官方規格 | OpenClaw (OC) | Hermes (HE) | opencode | SE Agent |
|---|---|---|---|---|---|
| 傳輸與端點 | 入站：HTTPS POST webhook（自行架站）；出站 `POST https://api.line.me/v2/bot/message/reply`、`/push`、`/multicast`、`/broadcast`；內容下載 `https://api-data.line.me/v2/bot/message/{id}/content` | express webhook + 自建 server（`extensions/line/src/webhook-node.ts`、`monitor.ts`） | aiohttp，`line/adapter.py:63-65` 預設 port 8646、路徑 `/line/webhook` | — | 內建 `seagent_net::httpd::Server`（`line.rs:58`）；`:31-32` api / data-api base，端點字串內嵌在 `:444`、`:460`、`:471`；`:13` 註解說明媒體由自己的 listener 服務 `/line/media/<token>/<file>` |
| 認證 | 出站 `Authorization: Bearer <channel access token>`（長效或短期）；webhook 不用 OAuth，靠 channel secret 的 HMAC | channel access token（`src/channel-access-token.ts`） | token 由 env 注入 | — | `:585` 建構 `Http::new(30s).bearer(token)`，之後所有請求共用；token 來自設定 |
| 入站事件 | `{destination, events:[{type, replyToken, source{userId/groupId/roomId}, timestamp, mode, message / postback / …}]}`；型別 message / postback / follow / join / leave / unsend / memberJoined… | `bot-handlers.ts`（`LINE_DOWNLOADABLE_MESSAGE_TYPES`，`:78`） | `line/adapter.py:546-551` 存 replyToken | — | `:6-8` text/image/video/audio/file/sticker/location、postback（→`Callback`）、user/group/room 三種 source、`mention.mentionees[].isSelf` 與 `@all`、`quotedMessageId`；follow/join/leave 只 ACK 丟棄 |
| 出站格式 | 一次請求 `messages[]` 1~5 個訊息物件；型別 text / image / video / audio / file / location / sticker / template / flex / imagemap；可掛 `quickReply` | `src/outbound.ts`、`message-cards.ts`、`flex-templates` | `line/adapter.py:244-248` reply/push 兩個端點 | — | `:437` 以 5 個為一批 `chunks(MAX_PER_CALL)`；`:215-222` 按鈕優先用 template buttons，塞不下改 quick reply；Markdown 一律降級成純文字（`:415-418`、`caps().markup=Plain`） |
| 長度上限與分段 | 單一 text 物件 5000 字元；每次請求 ≤5 個訊息物件；template/flex 需 `altText`（字數上限 ❓） | `outbound.ts:43` `textChunkLimit: 5000`、`monitor.ts:140` `textLimit=5000` | `adapter.py:58-60` 5000 / **安全值 4500** / 每呼叫 5 個 | — | `:34` `MAX_MESSAGE=5000`（字元）、`:35` `MAX_PER_CALL=5`、`:419` `chunk::split`；媒體說明文字另截斷（`:412`） |
| 速率限制 | 依方案限制每月訊息數；API 層有固定速率上限 ❓（官方未在可讀頁面確認具體 rps） | 由 `runLinePushWithRetries` 處理 429 ❓ | ❓ | — | `:262-271` push 遇 5xx／短 429 重試；`RateLimited` 由 `deliver.rs` 統一等 `retry_after` |
| 重連與重試 | 無長連線；webhook 需快速回 200，逾時 LINE 會重送（重送策略 ❓ 官方未確認次數/間隔） | `send-retry.ts` | ❓ | — | webhook 立即入佇列、由 `poll()` 取（`:380-394`）；push 帶 `X-Line-Retry-Key`（`:264-268`），收到 **409 視為已成功**（`:271`）以免重送兩次 |
| 錯誤碼處理 | 400 請求格式／reply token 失效、401 token 無效、403、429 超量、5xx；錯誤 body `{message, details[].message}` | `send.ts` 分類 | ❓ | — | reply token 失效（非 Auth 類錯誤）自動改 push（`:449-451`）；Auth 錯誤直接上拋不重試（`:449`）；其餘交 `classify()` |
| 簽章/驗證 | `X-Line-Signature` = **base64**(HMAC-SHA256(channel secret, raw body))，需常數時間比對 | `signature.ts:4-11` `createHmac("SHA256").digest("base64")` + `safeEqualSecret` | 同（`hmac` + `compare_digest`） | — | 同（`:4`）；`:2` 註解即寫明 base64 + HMAC-SHA256 + 常數時間 |
| 媒體 | 送圖/影片/音訊必須是**公開 HTTPS URL**（LINE 伺服器來抓）；`file` 訊息同理；下載走 `api-data.line.me` | `outbound-media.ts`、`download.ts`（`:13-16` 重試 6 次、退避 0.5→4s） | 同（public URL 限制，`:69-71`） | — | 本地檔由 SE Agent 自己的 listener 對外服務，需設 `public_url`（`:12-13`）；入站媒體從 `api-data.line.me` 下載 |
| 互動元件 | template buttons（一列最多 ❓、label ≤20 字）、confirm、carousel、flex、quick reply（≤13 項）、postback（`data` ≤300 字 ❓） | `actions.ts:14-31` 標籤 20、quick reply 13、data 300、uri 1000 | `adapter.py:75` postback label 20 字 | — | `:215-222` template buttons ≤4 顆且文字 ≤160 字，否則 quick reply chips（≤13）；`:11` postback 走 `Callback` |
| 已知差異 | reply token 一次性、約 60 秒內有效；push 另計費；有 loading animation API（僅 1:1） | 有 Flex/圖文選單指令（`card-command.ts`、`rich-messages.ts`），SE Agent 無 | 有「慢速 LLM」postback 按鈕機制（`adapter.py:71`、`:578`） | 無此協定 | `:10-11` reply 優先（免費、單次、保留 50 秒）、其餘 push；`:466-471` typing = loading animation，且只在 chat id 以 `U` 開頭（1:1）時送（`:468`） |

## SE Agent 的選擇與差異

- **reply token 只留 50 秒。** 官方約 60 秒，SE Agent 保守留 10 秒餘裕（`line.rs:36-37`）；HE 也取 50 秒（`adapter.py:61`），OC 的 TTL 未在原始碼中確認 ❓。token 一旦失效就自動降級 push（`:449-451`），使用者的訊息不會消失。
- **push 一定帶 `X-Line-Retry-Key`，且把 409 當成功。** `:264-271` 是本檔最關鍵的重試設計：LINE 對同一個 retry key 的第二次請求回 409，SE Agent 直接視為「前一次其實成功了」，避免重複訊息。OC 也做（`send.ts:317` 每個邏輯 push 一個 UUID），HE 沒有。
- **5000 字元切好切滿。** HE 保守用 4500（`adapter.py:59`），SE Agent 與 OC 都用滿 5000（`:34`、`outbound.ts:43`）；SE Agent 仍受「每次 5 個訊息」限制，所以超長訊息會拆成多個請求。
- **Markdown 一律轉純文字。** `caps().markup = Markup::Plain`（`:373`），LINE 沒有 markdown 方言，SE Agent 不做假支援；OC 另有 Flex 卡片與圖文選單指令，SE Agent 沒有。
- **按鈕只有兩段式降級。** ≤4 顆且文字 ≤160 走 template buttons，否則 quick reply（`:215-222`）；不像 Discord/Slack 有第三段（select/overflow）。
- **媒體要自己對外。** 本地檔靠 SE Agent 自己的 HTTP listener 掛在 `/line/media/<token>/<file>`（`:13`），必須設 `public_url`；這點與 HE 相同、與 OC 的「先上傳到 CDN ❓」不同。
- **quote 只在第一段。** `quoteToken` 掛在分段後的第一個 text 物件上（`:424-427`），語意是「回覆那則訊息」，其餘段落是純文字續傳。

## 上游實作位置

- OpenClaw：`extensions/line/`（`channel.ts`、`bot.ts`、`outbound.ts`、`signature.ts`、`send-retry.ts`、`flex-templates/`、`rich-messages.ts`）。
- Hermes：`plugins/platforms/line/adapter.py`（1001 行，aiohttp）。
- SE Agent：`crates/seagent-channel/src/line.rs`（857 行，含 `#[cfg(test)]`）；媒體由 `seagent_net::httpd::Server` 另開路徑服務（`:15`、`:13`）。
- SE Agent 共用：`chunk.rs`（分段）、`markup.rs`（Markdown→Plain）、`deliver.rs`（上層退避）。

## SE Agent 的測試覆蓋（全部離線）

- `:656` `signature_good_bad_missing_and_health`：簽章正確/錯誤/缺漏，與 health 端點。
- `:671` `parses_every_event_kind`：七種 message 型別 + postback + 三種 source + mention。
- `:720` `send_shapes_batches_buttons_media_and_serves_local_files`：5 個一批、template→quick reply 降級、本地檔對外服務。
- `:780` `reply_token_rejected_falls_back_to_push`：reply 被拒後改 push。
- `:795` `error_mapping_and_idempotent_retries`：5xx→429→成功、`X-Line-Retry-Key` 一致、409 視為成功（`:808-819`）。
- `:825` `fetch_media_uses_data_api_with_bearer`：`api-data.line.me` 下載。

## 未驗證清單

- 沒有 LINE 官方帳號：channel secret / access token 從未對 `api.line.me` 用過。
- reply token 的 50 秒 TTL 是保守估計，LINE 端實際失效點未觀察。
- quick reply 與 template buttons 的實際渲染（手機端）未看過。
- 圖文選單、Flex、imagemap、carousel 完全未實作，因此無法在真實帳號上比較。
- 每月訊息配額與 API 速率上限未知，`429` 的 `Retry-After` 是否會出現未觀察。
- loading animation（typing）只在 DM 有效這點來自文件敘述，未實跑。

## 端點使用範圍

SE Agent 實際只呼叫 `GET /v2/bot/info`（`:66`、`:329`，用於過濾自身訊息）、`POST /v2/bot/message/reply`（`:444`）、`POST /v2/bot/message/push`（`:460`）、`POST /v2/bot/chat/loading/start`（`:471`），並在啟動時 `PUT /v2/bot/channel/webhook/endpoint` 自動登記 webhook（`:524`、`:598`）。
媒體下載走 `api-data.line.me`，上限 200 MiB（`:482`、`:491`）。
**沒有** multicast / narrowcast / broadcast / rich menu / 圖文選單 / 群組摘要 API —— 需要大量推播的場景 SE Agent 只能逐個 chat push。
